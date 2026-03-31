package org.xiyu.githubdirect.dns;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Network;
import android.util.Log;

import org.xiyu.githubdirect.vpn.VirtualIpMap;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 从 github-hosts 项目自动同步 GitHub 域名的 IP 地址。
 * 数据源: https://gitee.com/TheDarkStar/github-hosts/raw/master/hosts
 * <p>
 * 同步策略:
 * - VPN 启动时立即同步一次
 * - 之后每 4 小时定期同步
 * - 同步结果持久化到 SharedPreferences
 * - 失败时沿用上次的结果或内置 IP
 */
public class HostsSyncer {

    private static final String TAG = "GithubDirect";
    private static final String HOSTS_URL =
            "https://gitee.com/TheDarkStar/github-hosts/raw/master/hosts";
    private static final int CONNECT_TIMEOUT = 8000;
    private static final int READ_TIMEOUT = 8000;
    private static final long SYNC_INTERVAL_HOURS = 4;

    private static final String PREFS_NAME = "github_hosts";
    private static final String KEY_HOSTS_DATA = "hosts_data";
    private static final String KEY_LAST_SYNC = "last_sync";

    private final Context context;
    private final Network underlyingNetwork;
    private ScheduledExecutorService scheduler;

    public HostsSyncer(Context context, Network underlyingNetwork) {
        this.context = context.getApplicationContext();
        this.underlyingNetwork = underlyingNetwork;
    }

    /**
     * 启动同步：先从缓存加载，然后异步拉取最新数据，之后定期刷新。
     */
    public void start() {
        // 1. 从缓存加载上次同步的数据
        loadCached();

        // 2. 立即异步同步一次
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "HostsSyncer");
            t.setDaemon(true);
            return t;
        });
        scheduler.schedule(this::syncNow, 0, TimeUnit.SECONDS);

        // 3. 定期同步
        scheduler.scheduleWithFixedDelay(this::syncNow,
                SYNC_INTERVAL_HOURS, SYNC_INTERVAL_HOURS, TimeUnit.HOURS);

        Log.i(TAG, "Hosts 同步已启动，间隔 " + SYNC_INTERVAL_HOURS + " 小时");
    }

    /**
     * 停止定期同步。
     */
    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    // relay 域名列表（SNI 被封锁），这些 IP 需要经过 TCP 连通性验证
    private static final String[] RELAY_DOMAINS = {
            "github.com", "api.github.com", "gist.github.com",
            "codeload.github.com", "alive.github.com", "central.github.com"
    };

    /**
     * 从缓存加载上次同步的 hosts 数据（所有域名，包括 relay）。
     * 无硬编码 IP，缓存是唯一的启动快速路径。
     */
    private void loadCached() {
        try {
            SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            String data = prefs.getString(KEY_HOSTS_DATA, null);
            long lastSync = prefs.getLong(KEY_LAST_SYNC, 0);
            if (data != null) {
                Map<String, String> hosts = parseHosts(data);
                if (!hosts.isEmpty()) {
                    VirtualIpMap.updateIps(hosts);
                    BuiltinIPs.updateIps(hosts);
                    Log.i(TAG, "从缓存加载 " + hosts.size() + " 条 hosts 记录"
                            + " (上次同步: " + ((System.currentTimeMillis() - lastSync) / 3600000) + "h ago)");
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "加载缓存 hosts 失败: " + e.getMessage());
        }
    }

    /**
     * 立即从远程拉取 hosts 数据。
     */
    private void syncNow() {
        try {
            String data = fetchHosts();
            if (data == null || data.isEmpty()) {
                Log.w(TAG, "Hosts 同步: 获取数据为空");
                return;
            }

            Map<String, String> hosts = parseHosts(data);
            if (hosts.isEmpty()) {
                Log.w(TAG, "Hosts 同步: 解析结果为空");
                return;
            }

            // 对 SNI 被封锁的域名（走 TCP relay）做 TCP 连通性验证
            // 不可达的 IP 不更新，保留原来的可用 IP
            validateRelayIps(hosts);

            // 更新运行时映射
            VirtualIpMap.updateIps(hosts);
            BuiltinIPs.updateIps(hosts);

            // 持久化
            SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            prefs.edit()
                    .putString(KEY_HOSTS_DATA, data)
                    .putLong(KEY_LAST_SYNC, System.currentTimeMillis())
                    .apply();

            Log.i(TAG, "Hosts 同步成功: " + hosts.size() + " 条记录");
        } catch (Exception e) {
            Log.w(TAG, "Hosts 同步失败: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * 对需要 TCP relay 的域名验证 IP 的 TCP 443 端口连通性。
     * 如果 github-hosts 返回的 IP 不可达，尝试通过 DoH（含海外服务器）获取可用 IP。
     */
    private void validateRelayIps(Map<String, String> hosts) {
        List<String> failedDomains = new ArrayList<>();

        // 第一轮：验证所有 relay IP
        for (String domain : RELAY_DOMAINS) {
            String ip = hosts.get(domain);
            if (ip == null) continue;

            if (isTcpReachable(ip, 443, 4000)) {
                Log.i(TAG, "IP 验证通过: " + domain + " → " + ip);
            } else {
                Log.w(TAG, "IP 验证失败 [不可达]: " + domain + " → " + ip);
                failedDomains.add(domain);
            }
        }

        // 第二轮：失败的域名尝试 DoH 获取新 IP（海外 DoH 可获取未污染的 IP）
        for (String domain : failedDomains) {
            String newIp = resolveViaDoH(domain);
            if (newIp != null && isTcpReachable(newIp, 443, 4000)) {
                hosts.put(domain, newIp);
                Log.i(TAG, "IP 替换为 DoH 解析: " + domain + " → " + newIp);
            } else {
                // 所有方式均失败，保留原始同步 IP（可能是网络临时问题）
                Log.w(TAG, "所有 IP 获取方式均失败: " + domain);
            }
        }
    }

    /**
     * 通过 DoH 解析域名，从所有 DoH 服务器收集 IP，逐个测试 TCP 443 可达性。
     * 不同 DoH 提供商可能返回不同的 Anycast IP，部分可能被 GFW 封锁。
     */
    private String resolveViaDoH(String domain) {
        try {
            InetAddress[] addrs = DohResolver.resolveAll(domain);
            if (addrs != null) {
                for (InetAddress addr : addrs) {
                    if (addr.getAddress().length != 4) continue; // 只用 IPv4
                    String ip = addr.getHostAddress();
                    if (isTcpReachable(ip, 443, 4000)) {
                        return ip;
                    }
                    Log.w(TAG, "DoH IP 不可达: " + domain + " → " + ip);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "DoH fallback 失败: " + domain + " - " + e.getMessage());
        }
        return null;
    }

    /**
     * 检测 IP:port 的 TCP 连通性。
     */
    private boolean isTcpReachable(String ip, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            if (underlyingNetwork != null) {
                underlyingNetwork.bindSocket(socket);
            }
            socket.connect(new InetSocketAddress(
                    InetAddress.getByName(ip), port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * HTTP GET 拉取 hosts 文件内容。
     */
    private String fetchHosts() throws Exception {
        URL url = new URL(HOSTS_URL);
        HttpURLConnection conn;
        if (underlyingNetwork != null) {
            conn = (HttpURLConnection) underlyingNetwork.openConnection(url);
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }
        conn.setConnectTimeout(CONNECT_TIMEOUT);
        conn.setReadTimeout(READ_TIMEOUT);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("User-Agent", "GithubDirect/1.0");

        try {
            int code = conn.getResponseCode();
            if (code != 200) {
                Log.w(TAG, "Hosts 拉取 HTTP " + code);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
            return sb.toString();
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 解析 hosts 文件格式: "IP domain" 每行一条。
     * 忽略注释行（#开头）和空行。
     *
     * @return domain → IP 映射
     */
    static Map<String, String> parseHosts(String data) {
        Map<String, String> result = new HashMap<>();
        if (data == null) return result;

        for (String line : data.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            // 格式: IP<空格>domain
            String[] parts = line.split("\\s+", 2);
            if (parts.length != 2) continue;

            String ip = parts[0].trim();
            String domain = parts[1].trim().toLowerCase();

            // 简单校验 IP 格式
            if (!ip.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) continue;

            result.put(domain, ip);
        }
        return result;
    }
}
