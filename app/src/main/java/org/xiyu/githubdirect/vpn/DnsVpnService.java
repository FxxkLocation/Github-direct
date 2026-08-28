package org.xiyu.githubdirect.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.xiyu.githubdirect.MainActivity;
import org.xiyu.githubdirect.R;
import org.xiyu.githubdirect.core.data.DiagLog;
import org.xiyu.githubdirect.core.dns.IpAddresses;
import org.xiyu.githubdirect.core.dns.PlainDnsClient;
import org.xiyu.githubdirect.core.dns.SelectiveDnsEngine;
import org.xiyu.githubdirect.core.dns.OkHttpWireDohTransport;
import org.xiyu.githubdirect.core.dns.WireDohClient;
import org.xiyu.githubdirect.core.net.VirtualIpPool;
import org.xiyu.githubdirect.core.rules.AppScopeMode;
import org.xiyu.githubdirect.core.rules.DomainPolicy;
import org.xiyu.githubdirect.core.rules.RuleMatch;
import org.xiyu.githubdirect.core.rules.RuleRegistry;
import org.xiyu.githubdirect.data.DirectEngine;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 直连代理 VPN 服务（TUN 生命周期 / 通知 / protect 注入保留，策略分发移出）。
 * <p>
 * M1 重构后职责：
 * - 创建 TUN 接口，拦截全部流量
 * - UDP 53 查询 → VpnDnsHandler 薄壳 + SelectiveDnsEngine（raw 转发优先，目标域合成）
 * - TCP 到 vIP → TcpRelay（真实 IP + TLS 分片，RouteTarget 参数对象）
 * - TCP/53 到假 DNS（10.0.0.2）→ TcpRelay 明文上游透传（§30）
 * - 网络绑定/自发出流量经 VpnNetworkBinder（NetworkCallback 维护底层网络）
 */
public class DnsVpnService extends VpnService {

    private static final String TAG = "DirectProxy";
    private static final String CHANNEL_ID = "direct_proxy_vpn";
    private static final int NOTIFICATION_ID = 1;

    private static final String VPN_ADDRESS = "10.0.0.1";
    private static final String FAKE_DNS = "10.0.0.2";
    private static final String VIRTUAL_IP_ROUTE = "10.0.0.0"; // 虚拟 IP 段
    private static final int VIRTUAL_IP_PREFIX = 24;
    private static final int DNS_PORT = 53;
    private static final int VPN_MTU = 1500;

    /** §30：TCP/53 明文上游（字节透传目标；IP 字面量，免递归 DNS）。 */
    private static final byte[] PLAIN_DNS_UPSTREAM = IpAddresses.parseIpv4("223.5.5.5");

    public static final String ACTION_START = "org.xiyu.githubdirect.VPN_START";
    public static final String ACTION_STOP = "org.xiyu.githubdirect.VPN_STOP";

    private ParcelFileDescriptor vpnInterface;
    private volatile boolean running;
    private TcpRelay tcpRelay;
    private FileOutputStream tunOut;
    private ExecutorService dnsExecutor;
    private VpnNetworkBinder binder;
    private VpnDnsHandler dnsHandler;
    private VirtualIpPool pool;
    private RuleRegistry registry;

    /** 非 53 端口 UDP 丢包计数（诊断模式才累计，见 handleIncomingPacket）。 */
    private final AtomicLong udpDropped = new AtomicLong();

    private static volatile boolean active = false;

    public static boolean isActive() {
        return active;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }
        startVpn();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopVpn();
        stopSelf();
    }

    // ==================== VPN 生命周期 ====================

    private void startVpn() {
        if (running) return;

        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification());

        try {
            // 引擎装配（规则 / DoH / vIP 池 / hosts 同步）
            if (!DirectEngine.ensureInit(this, true)) {
                Log.e(TAG, "引擎初始化失败，VPN 无法启动");
                stopSelf();
                return;
            }
            binder = (VpnNetworkBinder) DirectEngine.binder();
            if (binder == null) {
                Log.e(TAG, "NetworkBinder 不可用");
                stopSelf();
                return;
            }
            binder.start();
            // 自发出流量（hosts 同步/DoH）绑定底层物理网络；TcpRelay 的 socket 走 protect
            binder.setProtect(socket -> DnsVpnService.this.protect(socket));
            pool = DirectEngine.pool();
            registry = DirectEngine.registry();

            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addDnsServer(FAKE_DNS);
            builder.addRoute(FAKE_DNS, 32);       // DNS 流量路由
            builder.addRoute(VIRTUAL_IP_ROUTE, VIRTUAL_IP_PREFIX); // 虚拟 IP 路由（TCP relay）
            builder.setMtu(VPN_MTU);
            builder.setSession("直连代理");
            builder.setBlocking(false);
            applyAppScope(builder); // 应用范围（§40/§67 注入安全延伸）

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "VPN establish failed (需要用户授权)");
                binder.stop();
                stopSelf();
                return;
            }

            running = true;
            active = true;

            // DNS 处理线程池（固定 4 线程，避免阻塞 VPN 主循环）
            dnsExecutor = Executors.newFixedThreadPool(4, r -> {
                Thread t = new Thread(r, "DNS-Fwd");
                t.setDaemon(true);
                return t;
            });

            // Phase 2：选择性 DNS 引擎（raw wire DoH 优先 → 明文 UDP 回退），VpnDnsHandler 薄壳。
            // 优先用 DirectEngine 共享单例（Root 后端与 VPN 复用同一引擎）；防御性回退自建。
            SelectiveDnsEngine dnsEngine = DirectEngine.dnsEngine();
            if (dnsEngine == null) {
                WireDohClient wire = OkHttpWireDohTransport.createClient(binder);
                PlainDnsClient plain = new PlainDnsClient();
                dnsEngine = new SelectiveDnsEngine(
                        DirectEngine.registry(),
                        DirectEngine.resolver(),
                        DirectEngine.cache(),
                        DirectEngine.pool(),
                        DirectEngine.relayTable(),
                        wire,
                        plain);
            }
            dnsHandler = new VpnDnsHandler(
                    DirectEngine.registry(),
                    DirectEngine.resolver(),
                    DirectEngine.cache(),
                    DirectEngine.pool(),
                    DirectEngine.relayTable(),
                    dnsEngine);

            new Thread(this::vpnLoop, "DirectVPN-Worker").start();
            Log.i(TAG, "直连代理已启动");
        } catch (Exception e) {
            Log.e(TAG, "VPN 启动失败", e);
            stopSelf();
        }
    }

    private void stopVpn() {
        running = false;
        active = false;
        if (binder != null) {
            // 只撤掉 VpnService.protect；不要 unregister / stopProviders。
            // 用户切到 Root 时 STOP 是异步的，否则会把刚拉起的 github-hosts 和 DoH 网络绑定拆掉。
            binder.setProtect(null);
            binder = null;
        }
        if (dnsExecutor != null) {
            dnsExecutor.shutdownNow();
            dnsExecutor = null;
        }
        if (tcpRelay != null) {
            tcpRelay.stop();
            tcpRelay = null;
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
        tunOut = null;
        dnsHandler = null;
        Log.i(TAG, "直连代理已停止");
    }

    // ==================== 数据包处理循环 ====================

    private void vpnLoop() {
        try (FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor())) {

            tunOut = out;

            // TCP Relay：会话租约经 vIP 池（refs 钉住映射，防 LRU 驱逐）
            DnsVpnService self = this;
            tcpRelay = new TcpRelay(
                    socket -> self.protect(socket),
                    packet -> {
                        synchronized (out) {
                            try {
                                out.write(packet);
                            } catch (Exception e) {
                                Log.w(TAG, "TUN write from relay: " + e.getMessage());
                            }
                        }
                    },
                    new TcpRelay.SessionLeaseHook() {
                        @Override
                        public void onSessionOpen(int vip) {
                            pool.lease(vip);
                        }

                        @Override
                        public void onSessionClose(int vip) {
                            pool.release(vip);
                        }
                    },
                    128
            );

            byte[] buffer = new byte[VPN_MTU];
            while (running) {
                int length = in.read(buffer);
                if (length <= 0) {
                    Thread.sleep(5);
                    continue;
                }

                byte[] packet = Arrays.copyOf(buffer, length);
                handleIncomingPacket(packet, out);
            }
        } catch (Exception e) {
            if (running) {
                Log.e(TAG, "VPN 循环异常", e);
            }
        } finally {
            active = false;
        }
    }

    /**
     * 分类处理 TUN 收到的数据包：UDP DNS → VpnDnsHandler；TCP → vIP 映射 + TcpRelay。
     */
    private void handleIncomingPacket(byte[] packet, FileOutputStream out) {
        if (packet.length < 20) return;

        int version = (packet[0] >> 4) & 0xF;
        if (version != 4) return;

        int ipHeaderLen = (packet[0] & 0xF) * 4;
        int protocol = packet[9] & 0xFF;

        if (protocol == 6 && packet.length >= ipHeaderLen + 20) {
            handleTcp(packet, ipHeaderLen, out);
            return;
        }

        if (protocol == 17) {
            // UDP — DNS 处理（异步，避免阻塞 VPN 主循环）
            if (packet.length >= ipHeaderLen + 8 + 12) {
                int dstPort = readU16(packet, ipHeaderLen + 2);
                if (dstPort == DNS_PORT) {
                    final byte[] pkt = packet;
                    final int hdrLen = ipHeaderLen;
                    ExecutorService exec = dnsExecutor;
                    if (exec != null && !exec.isShutdown()) {
                        exec.submit(() -> {
                            byte[] response = dnsHandler != null ? dnsHandler.handle(pkt, hdrLen) : null;
                            if (response != null) {
                                writeTun(out, response);
                            }
                        });
                    }
                } else if (DiagLog.INSTANCE.isEnabled()) {
                    // 非 53 端口 UDP（QUIC/HTTP3 等）：relay 域靠客户端 TCP 回退，静默丢弃（设计 §5）
                    udpDropped.incrementAndGet();
                    if (udpDropped.get() % 100 == 1) {
                        Log.d(TAG, "UDP 非 53 端口静默丢弃累计: " + udpDropped.get()
                                + " (dstPort=" + dstPort + ")");
                    }
                }
            }
        }
    }

    /**
     * TCP 到 vIP：查池映射 → RouteTarget（真实 IP / 分片 / 空闲超时）→ TcpRelay。
     * lookupReal 无映射 → 回 RST（消除静默丢包挂起）。
     */
    private void handleTcp(byte[] packet, int ipHeaderLen, FileOutputStream out) {
        byte[] dstIp = Arrays.copyOfRange(packet, 16, 20);
        int dstPort = readU16(packet, ipHeaderLen + 2);

        // §30: TCP/53 到假 DNS（10.0.0.2）→ 明文上游 DNS 服务器字节透传
        // （TCP DNS 流的 2 字节 framing 内含于数据流，无需解析，无分片）
        if (dstPort == DNS_PORT && isFakeDns(dstIp)) {
            if (tcpRelay != null) {
                tcpRelay.handlePacket(packet, ipHeaderLen,
                        new TcpRelay.RouteTarget(PLAIN_DNS_UPSTREAM, false, 60));
            }
            return;
        }

        if (pool == null || !pool.isVirtualIp(dstIp)) return;

        int vip = ipToInt(dstIp);
        VirtualIpPool.Mapping mapping = pool.lookupReal(vip);
        if (mapping == null) {
            Log.w(TAG, "TCP 到无映射 vIP，回 RST");
            byte[] rst = TcpRelay.buildRst(packet, ipHeaderLen);
            if (rst != null) writeTun(out, rst);
            return;
        }

        // 取策略参数（分片开关 / 空闲超时）
        boolean fragmentTls = true;
        int idleTimeoutSec = 60;
        if (registry != null) {
            RuleMatch match = registry.match(mapping.getDomain());
            if (match != null) {
                DomainPolicy p = match.getPolicy();
                fragmentTls = p.getFragmentTls();
                idleTimeoutSec = p.getIdleTimeoutSec();
            }
        }
        tcpRelay.handlePacket(packet, ipHeaderLen,
                new TcpRelay.RouteTarget(mapping.getV4(), fragmentTls, idleTimeoutSec));
    }

    // ==================== App Scope（§40） ====================

    /**
     * 按 SettingsStore 的 scope 配置应用 VpnService.Builder 的应用过滤：
     * - ALL_APPS：不加任何过滤
     * - SELECTED_APPS → addAllowedApplication（白名单）
     * - EXCLUDED_APPS → addDisallowedApplication（黑名单）
     *
     * 包名来自我方设置，仍做正则校验过滤非法包名（§67 注入安全延伸——
     * Builder 参数只接受包名字符串，非法包名建立后会被系统忽略，但校验可防御脏数据）。
     * SELECTED 无有效包名 → 回退全部应用（空白名单 = 拦截一切，必须避免）。
     */
    private void applyAppScope(Builder builder) {
        org.xiyu.githubdirect.core.data.SettingsStore settings = DirectEngine.settings();
        if (settings == null) return;
        AppScopeMode mode = settings.appScopeMode();
        if (mode == AppScopeMode.ALL_APPS) return;
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("^[a-zA-Z][a-zA-Z0-9_.]*$");
        int applied = 0;
        for (String pkg : settings.scopedPackages()) {
            if (pkg == null || !p.matcher(pkg).matches()) continue;
            try {
                if (mode == AppScopeMode.SELECTED_APPS) {
                    builder.addAllowedApplication(pkg);
                } else {
                    builder.addDisallowedApplication(pkg);
                }
                applied++;
            } catch (android.content.pm.PackageManager.NameNotFoundException e) {
                Log.w(TAG, "scope 包未安装，跳过: " + pkg);
            }
        }
        if (mode == AppScopeMode.SELECTED_APPS && applied == 0) {
            Log.w(TAG, "SELECTED scope 无有效包名，回退全部应用");
        }
    }

    // ==================== TUN 写入 ====================

    private void writeTun(FileOutputStream out, byte[] data) {
        if (data == null || out == null) return;
        try {
            synchronized (out) {
                out.write(data);
            }
        } catch (Exception e) {
            Log.w(TAG, "TUN write: " + e.getMessage());
        }
    }

    // ==================== 工具方法 ====================

    private static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int ipToInt(byte[] ip) {
        return ((ip[0] & 0xFF) << 24) | ((ip[1] & 0xFF) << 16)
                | ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
    }

    private static boolean isFakeDns(byte[] ip) {
        return ip.length == 4 && ip[0] == 10 && ip[1] == 0 && ip[2] == 0 && ip[3] == 2;
    }

    // ==================== 通知 ====================

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "直连代理",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("直连代理运行状态通知");
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) nm.createNotificationChannel(channel);
    }

    private Notification buildNotification() {
        Intent stopIntent = new Intent(this, DnsVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPi = PendingIntent.getService(
                this, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE);

        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent mainPi = PendingIntent.getActivity(
                this, 0, mainIntent, PendingIntent.FLAG_IMMUTABLE);

        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("直连代理")
                .setContentText("DNS + TCP 代理运行中")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(mainPi)
                .addAction(new Notification.Action.Builder(
                        null, "停止", stopPi).build())
                .setOngoing(true)
                .build();
    }
}
