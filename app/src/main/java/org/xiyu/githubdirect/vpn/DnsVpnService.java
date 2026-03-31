package org.xiyu.githubdirect.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.xiyu.githubdirect.MainActivity;
import org.xiyu.githubdirect.R;
import org.xiyu.githubdirect.dns.BuiltinIPs;
import org.xiyu.githubdirect.dns.DnsCache;
import org.xiyu.githubdirect.dns.DohResolver;
import org.xiyu.githubdirect.dns.GithubDomains;
import org.xiyu.githubdirect.dns.HostsSyncer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * VPN 本地 DNS 代理服务。
 * <p>
 * 通过创建 TUN 接口拦截所有 DNS 查询：
 * - GitHub 域名：使用 BuiltinIPs / DoH 解析为可达 IP
 * - 其他域名：转发到真实 DNS 服务器 (Alidns)
 */
public class DnsVpnService extends VpnService {

    private static final String TAG = "GithubDirect";
    private static final String CHANNEL_ID = "github_direct_vpn";
    private static final int NOTIFICATION_ID = 1;

    private static final String VPN_ADDRESS = "10.0.0.1";
    private static final String FAKE_DNS = "10.0.0.2";
    private static final String VIRTUAL_IP_ROUTE = "10.0.0.0"; // 虚拟 IP 段
    private static final int VIRTUAL_IP_PREFIX = 24;
    private static final int DNS_PORT = 53;
    private static final int VPN_MTU = 1500;

    public static final String ACTION_START = "org.xiyu.githubdirect.VPN_START";
    public static final String ACTION_STOP = "org.xiyu.githubdirect.VPN_STOP";

    private ParcelFileDescriptor vpnInterface;
    private volatile boolean running;
    private TcpRelay tcpRelay;
    private HostsSyncer hostsSyncer;
    private FileOutputStream tunOut;
    private ExecutorService dnsExecutor;
    private Network underlyingNetwork;

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
            // 保存底层物理网络（VPN建立后需要它来绕过VPN做DNS转发和同步）
            try {
                ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                Network activeNet = cm.getActiveNetwork();
                if (activeNet != null) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(activeNet);
                    if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        underlyingNetwork = activeNet;
                        Log.i(TAG, "底层网络已保存: " + activeNet);
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "获取底层网络失败(权限不足?): " + e.getMessage());
            }

            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addDnsServer(FAKE_DNS);
            builder.addRoute(FAKE_DNS, 32);       // DNS 流量路由
            builder.addRoute(VIRTUAL_IP_ROUTE, VIRTUAL_IP_PREFIX); // 虚拟 IP 路由（TCP relay）
            builder.setMtu(VPN_MTU);
            builder.setSession("GitHub 直连");
            builder.setBlocking(false);

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "VPN establish failed (需要用户授权)");
                stopSelf();
                return;
            }

            running = true;
            active = true;

            // DNS 转发线程池（避免阻塞 VPN 主循环）
            dnsExecutor = Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "DNS-Fwd");
                t.setDaemon(true);
                return t;
            });

            // 启动 hosts 自动同步
            hostsSyncer = new HostsSyncer(this, underlyingNetwork);
            hostsSyncer.start();

            // 让 DohResolver 在 VPN 服务进程中也使用底层网络
            DohResolver.setNetwork(underlyingNetwork);

            new Thread(this::vpnLoop, "DnsVPN-Worker").start();
            Log.i(TAG, "VPN DNS+TCP 代理已启动（SNI bypass 已启用）");
        } catch (Exception e) {
            Log.e(TAG, "VPN 启动失败", e);
            stopSelf();
        }
    }

    private void stopVpn() {
        running = false;
        active = false;
        DohResolver.setNetwork(null);
        if (hostsSyncer != null) {
            hostsSyncer.stop();
            hostsSyncer = null;
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
        Log.i(TAG, "VPN DNS+TCP 代理已停止");
    }

    // ==================== 数据包处理循环 ====================

    private void vpnLoop() {
        try (FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor())) {

            tunOut = out;

            // 初始化 TCP Relay（ClientHello 分片绕过 SNI 检测）
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
                    }
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
     * 分类处理 TUN 收到的数据包：UDP DNS 走 DNS 处理，TCP 到虚拟 IP 走 TCP Relay。
     */
    private void handleIncomingPacket(byte[] packet, FileOutputStream out) {
        if (packet.length < 20) return;

        int version = (packet[0] >> 4) & 0xF;
        if (version != 4) return;

        int ipHeaderLen = (packet[0] & 0xF) * 4;
        int protocol = packet[9] & 0xFF;

        if (protocol == 6 && packet.length >= ipHeaderLen + 20) {
            // TCP — 检查是否发往虚拟 IP
            byte[] dstIp = Arrays.copyOfRange(packet, 16, 20);
            String dstIpStr = (dstIp[0] & 0xFF) + "." + (dstIp[1] & 0xFF) + "."
                    + (dstIp[2] & 0xFF) + "." + (dstIp[3] & 0xFF);
            int dstPort = readU16(packet, ipHeaderLen + 2);
            int tcpFlags = packet[ipHeaderLen + 13] & 0xFF;
            Log.d(TAG, "TCP packet → " + dstIpStr + ":" + dstPort
                    + " flags=0x" + Integer.toHexString(tcpFlags)
                    + " isVirtual=" + VirtualIpMap.isVirtualIp(dstIp));
            if (VirtualIpMap.isVirtualIp(dstIp)) {
                byte[] realIp = VirtualIpMap.getRealIp(dstIp);
                if (realIp != null) {
                    tcpRelay.handlePacket(packet, ipHeaderLen, realIp);
                } else {
                    Log.w(TAG, "TCP 无真实 IP 映射: " + dstIpStr);
                }
            }
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
                            byte[] response = handleDnsPacket(pkt, hdrLen);
                            if (response != null) {
                                writeTun(out, response);
                            }
                        });
                    }
                }
            }
        }
    }

    // ==================== IP + UDP + DNS 数据包处理 ====================

    /**
     * 处理 DNS 查询数据包（UDP port 53）。
     */
    private byte[] handleDnsPacket(byte[] packet, int ipHeaderLen) {
        if (packet.length < ipHeaderLen + 8 + 12) return null;

        int dstPort = readU16(packet, ipHeaderLen + 2);
        if (dstPort != DNS_PORT) return null;

        int udpLen = readU16(packet, ipHeaderLen + 4);
        int dnsOffset = ipHeaderLen + 8;
        int dnsLen = udpLen - 8;

        if (dnsLen < 12 || dnsOffset + dnsLen > packet.length) return null;

        byte[] dnsQuery = Arrays.copyOfRange(packet, dnsOffset, dnsOffset + dnsLen);

        String domain = parseDnsDomain(dnsQuery);
        int queryType = getQueryType(dnsQuery);

        Log.d(TAG, "DNS 查询: " + domain + " (type=" + queryType + ")");

        byte[] dnsResponse;
        if (domain != null && GithubDomains.isGithubDomain(domain)) {
            dnsResponse = resolveGithubDomain(dnsQuery, domain, queryType);
            if (dnsResponse != null) {
                Log.i(TAG, "GitHub DNS 本地解析: " + domain);
            }
        } else {
            dnsResponse = forwardToRealDns(dnsQuery);
        }

        if (dnsResponse == null) {
            dnsResponse = buildServFailResponse(dnsQuery);
        }

        return constructIpPacket(packet, ipHeaderLen, dnsResponse);
    }

    // ==================== GitHub 域名解析 ====================

    private byte[] resolveGithubDomain(byte[] dnsQuery, String domain, int queryType) {
        // SNI 被封锁的域名：返回虚拟 IP，流量走 TCP Relay + ClientHello 分片
        String virtualIp = VirtualIpMap.getVirtualIp(domain);
        if (virtualIp != null && queryType == 1) { // 仅 A 记录使用虚拟 IP
            try {
                InetAddress vAddr = InetAddress.getByName(virtualIp);
                Log.i(TAG, "SNI bypass: " + domain + " → " + virtualIp + " (virtual)");
                return buildDnsResponse(dnsQuery, domain, new InetAddress[]{vAddr}, queryType);
            } catch (Exception e) {
                Log.w(TAG, "虚拟 IP 解析失败: " + virtualIp);
            }
        }

        // CDN 域名或 AAAA 查询：返回直连 IP
        String directIp = VirtualIpMap.getDirectIp(domain);
        if (directIp != null && queryType == 1) {
            try {
                InetAddress dAddr = InetAddress.getByName(directIp);
                return buildDnsResponse(dnsQuery, domain, new InetAddress[]{dAddr}, queryType);
            } catch (Exception ignored) {
            }
        }

        // 回退到 BuiltinIPs
        InetAddress[] addrs = BuiltinIPs.lookup(domain);

        // 其次尝试 DoH
        if (addrs == null || addrs.length == 0) {
            try {
                addrs = DohResolver.resolve(domain);
            } catch (Exception e) {
                Log.w(TAG, "DoH 解析失败: " + domain);
            }
        }

        if (addrs == null || addrs.length == 0) return null;

        return buildDnsResponse(dnsQuery, domain, addrs, queryType);
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

    // ==================== DNS 转发（非 GitHub 域名）====================

    // DoH 服务器列表（HTTPS，避免 UDP 被屏蔽）
    private static final String[] FORWARD_DOH_SERVERS = {
            "https://223.5.5.5/dns-query",    // Alidns
            "https://1.12.12.12/dns-query",   // DNSPod
    };

    /**
     * 通过 DoH (HTTPS) 转发非 GitHub 的 DNS 查询。
     * UDP DNS 在部分设备/运营商上被屏蔽，DoH 更可靠。
     */
    private byte[] forwardToRealDns(byte[] dnsQuery) {
        String domain = parseDnsDomain(dnsQuery);
        int queryType = getQueryType(dnsQuery);
        if (domain == null) return null;

        for (String server : FORWARD_DOH_SERVERS) {
            try {
                String typeStr = queryType == 28 ? "AAAA" : "A";
                String urlStr = server + "?name=" + java.net.URLEncoder.encode(domain, "UTF-8")
                        + "&type=" + typeStr;
                java.net.HttpURLConnection conn;
                java.net.URL url = new java.net.URL(urlStr);
                if (underlyingNetwork != null) {
                    conn = (java.net.HttpURLConnection) underlyingNetwork.openConnection(url);
                } else {
                    conn = (java.net.HttpURLConnection) url.openConnection();
                }
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Accept", "application/dns-json");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);

                try {
                    int code = conn.getResponseCode();
                    if (code != 200) continue;

                    StringBuilder sb = new StringBuilder();
                    try (java.io.BufferedReader reader = new java.io.BufferedReader(
                            new java.io.InputStreamReader(conn.getInputStream(), "UTF-8"))) {
                        String line;
                        while ((line = reader.readLine()) != null) sb.append(line);
                    }

                    InetAddress[] addrs = parseDoHForward(sb.toString(), domain);
                    if (addrs != null && addrs.length > 0) {
                        return buildDnsResponse(dnsQuery, domain, addrs, queryType);
                    }
                } finally {
                    conn.disconnect();
                }
            } catch (Exception e) {
                Log.w(TAG, "DNS DoH 转发失败 (" + server + "): " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * 解析 DoH JSON 响应（通用，不做 IP 范围校验）。
     */
    private InetAddress[] parseDoHForward(String json, String host) {
        try {
            org.json.JSONObject root = new org.json.JSONObject(json);
            int status = root.optInt("Status", -1);
            if (status != 0) return null;

            org.json.JSONArray answers = root.optJSONArray("Answer");
            if (answers == null) return null;

            java.util.List<InetAddress> result = new java.util.ArrayList<>();
            for (int i = 0; i < answers.length(); i++) {
                org.json.JSONObject answer = answers.getJSONObject(i);
                int type = answer.getInt("type");
                if (type != 1 && type != 28) continue; // A or AAAA only

                String data = answer.getString("data");
                byte[] addrBytes = DohResolver.parseIpAddress(data);
                if (addrBytes != null) {
                    result.add(InetAddress.getByAddress(host, addrBytes));
                }
            }
            return result.isEmpty() ? null : result.toArray(new InetAddress[0]);
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== DNS 协议解析 ====================

    /**
     * 从 DNS 查询中解析域名。
     * DNS 域名格式: [长度][标签][长度][标签]...[0]
     * 例如: \x06github\x03com\x00 = github.com
     */
    private String parseDnsDomain(byte[] dns) {
        if (dns.length < 13) return null;

        StringBuilder sb = new StringBuilder();
        int pos = 12; // 跳过 DNS 头 (12 bytes)

        while (pos < dns.length) {
            int labelLen = dns[pos] & 0xFF;
            if (labelLen == 0) break;

            // 检查是否为指针 (0xC0xx)
            if ((labelLen & 0xC0) == 0xC0) break;

            if (pos + 1 + labelLen > dns.length) return null;
            if (sb.length() > 0) sb.append('.');

            for (int i = 0; i < labelLen; i++) {
                sb.append((char) (dns[pos + 1 + i] & 0xFF));
            }
            pos += 1 + labelLen;
        }

        return sb.length() > 0 ? sb.toString().toLowerCase() : null;
    }

    /**
     * 获取 DNS 查询类型 (QTYPE)。
     * 位于 Question Section 的域名之后。
     */
    private int getQueryType(byte[] dns) {
        int pos = 12;
        // 跳过域名
        while (pos < dns.length) {
            int labelLen = dns[pos] & 0xFF;
            if (labelLen == 0) {
                pos++;
                break;
            }
            if ((labelLen & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += 1 + labelLen;
        }
        if (pos + 2 <= dns.length) {
            return readU16(dns, pos);
        }
        return 0;
    }

    /**
     * 获取 Question Section 的结束位置。
     */
    private int getQuestionEnd(byte[] dns) {
        int pos = 12;
        while (pos < dns.length) {
            int labelLen = dns[pos] & 0xFF;
            if (labelLen == 0) {
                pos++;
                break;
            }
            if ((labelLen & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += 1 + labelLen;
        }
        // QTYPE (2) + QCLASS (2)
        return pos + 4;
    }

    // ==================== DNS 响应构造 ====================

    /**
     * 构造 DNS 响应包（仅包含 A/AAAA 记录）。
     */
    private byte[] buildDnsResponse(byte[] query, String domain, InetAddress[] addrs, int queryType) {
        int questionEnd = getQuestionEnd(query);
        if (questionEnd > query.length) return null;

        // 筛选匹配查询类型的地址
        int answerCount = 0;
        for (InetAddress addr : addrs) {
            byte[] raw = addr.getAddress();
            if (queryType == 1 && raw.length == 4) answerCount++;       // A 记录
            else if (queryType == 28 && raw.length == 16) answerCount++; // AAAA 记录
        }

        if (answerCount == 0) {
            // 返回 NOERROR 但无答案（表示该类型无记录）
            return buildEmptyResponse(query, questionEnd);
        }

        // 计算响应大小
        int answerSize = 0;
        for (InetAddress addr : addrs) {
            byte[] raw = addr.getAddress();
            if (queryType == 1 && raw.length == 4) answerSize += 16;      // 2+2+2+4+2+4
            else if (queryType == 28 && raw.length == 16) answerSize += 28; // 2+2+2+4+2+16
        }

        byte[] response = new byte[questionEnd + answerSize];

        // 复制 DNS 头和 Question Section
        System.arraycopy(query, 0, response, 0, questionEnd);

        // 设置响应标志
        response[2] = (byte) 0x81; // QR=1, OPCODE=0, AA=0, TC=0, RD=1
        response[3] = (byte) 0x80; // RA=1, RCODE=0 (NOERROR)

        // ANCOUNT
        response[6] = (byte) ((answerCount >> 8) & 0xFF);
        response[7] = (byte) (answerCount & 0xFF);

        // NSCOUNT = 0, ARCOUNT = 0
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;

        // 写入 Answer Records
        int pos = questionEnd;
        for (InetAddress addr : addrs) {
            byte[] raw = addr.getAddress();
            boolean isV4 = raw.length == 4;

            if (queryType == 1 && !isV4) continue;
            if (queryType == 28 && isV4) continue;

            // Name: 指针到 offset 12 (域名在 Question Section)
            response[pos++] = (byte) 0xC0;
            response[pos++] = 0x0C;

            // Type
            writeU16(response, pos, isV4 ? 1 : 28);
            pos += 2;

            // Class: IN (1)
            writeU16(response, pos, 1);
            pos += 2;

            // TTL: 300 秒
            writeU32(response, pos, 300);
            pos += 4;

            // RDLENGTH
            writeU16(response, pos, raw.length);
            pos += 2;

            // RDATA: IP 地址
            System.arraycopy(raw, 0, response, pos, raw.length);
            pos += raw.length;
        }

        return response;
    }

    private byte[] buildEmptyResponse(byte[] query, int questionEnd) {
        byte[] response = new byte[questionEnd];
        System.arraycopy(query, 0, response, 0, questionEnd);
        response[2] = (byte) 0x81;
        response[3] = (byte) 0x80;
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;
        return response;
    }

    private byte[] buildServFailResponse(byte[] query) {
        int questionEnd = getQuestionEnd(query);
        if (questionEnd > query.length) questionEnd = Math.min(query.length, 12);
        byte[] response = new byte[questionEnd];
        System.arraycopy(query, 0, response, 0, Math.min(query.length, questionEnd));
        if (response.length >= 4) {
            response[2] = (byte) 0x81;
            response[3] = (byte) 0x82; // RCODE=2 (SERVFAIL)
        }
        return response;
    }

    // ==================== IP 数据包构造 ====================

    /**
     * 将 DNS 响应封装为 IPv4 + UDP 数据包。
     * 交换原始查询包的源/目标地址和端口。
     */
    private byte[] constructIpPacket(byte[] queryPacket, int ipHeaderLen, byte[] dnsResponse) {
        int udpLen = 8 + dnsResponse.length;
        int totalLen = 20 + udpLen;  // 使用标准 20 字节 IPv4 头

        byte[] response = new byte[totalLen];

        // ---- IPv4 Header ----
        response[0] = 0x45;                // Version=4, IHL=5 (20 bytes)
        response[1] = 0;                   // DSCP/ECN
        writeU16(response, 2, totalLen);    // Total Length
        writeU16(response, 4, 0);           // Identification
        writeU16(response, 6, 0x4000);      // Flags: Don't Fragment
        response[8] = 64;                  // TTL
        response[9] = 17;                  // Protocol: UDP

        // 源 IP = 原始查询的目标 IP (fake DNS)
        System.arraycopy(queryPacket, 16, response, 12, 4);
        // 目标 IP = 原始查询的源 IP (client)
        System.arraycopy(queryPacket, 12, response, 16, 4);

        // IP Checksum
        writeU16(response, 10, 0);
        writeU16(response, 10, ipChecksum(response, 0, 20));

        // ---- UDP Header ----
        int udpOffset = 20;
        // 源端口 = 原始查询的目标端口 (53)
        System.arraycopy(queryPacket, ipHeaderLen + 2, response, udpOffset, 2);
        // 目标端口 = 原始查询的源端口
        System.arraycopy(queryPacket, ipHeaderLen, response, udpOffset + 2, 2);
        writeU16(response, udpOffset + 4, udpLen);
        writeU16(response, udpOffset + 6, 0);  // UDP checksum = 0 (可选)

        // ---- DNS Response ----
        System.arraycopy(dnsResponse, 0, response, udpOffset + 8, dnsResponse.length);

        return response;
    }

    // ==================== 工具方法 ====================

    private static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static void writeU16(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }

    private static void writeU32(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >> 24) & 0xFF);
        data[offset + 1] = (byte) ((value >> 16) & 0xFF);
        data[offset + 2] = (byte) ((value >> 8) & 0xFF);
        data[offset + 3] = (byte) (value & 0xFF);
    }

    private static int ipChecksum(byte[] data, int offset, int length) {
        long sum = 0;
        for (int i = 0; i < length; i += 2) {
            int word;
            if (i + 1 < length) {
                word = ((data[offset + i] & 0xFF) << 8) | (data[offset + i + 1] & 0xFF);
            } else {
                word = (data[offset + i] & 0xFF) << 8;
            }
            sum += word;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum & 0xFFFF);
    }

    // ==================== 通知 ====================

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "GitHub 直连 DNS 代理",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("DNS 代理运行状态通知");
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
                .setContentTitle("GitHub 直连")
                .setContentText("DNS + TCP 代理运行中 — GitHub SNI bypass 已启用")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(mainPi)
                .addAction(new Notification.Action.Builder(
                        null, "停止", stopPi).build())
                .setOngoing(true)
                .build();
    }
}
