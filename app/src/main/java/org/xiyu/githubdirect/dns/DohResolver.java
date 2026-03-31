package org.xiyu.githubdirect.dns;

import android.net.Network;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class DohResolver {

    private static final String TAG = "GithubDirect";

    /** VPN 服务进程中使用的底层物理网络，绕过 VPN 路由 */
    private static volatile Network sNetwork;

    // 国内 DoH 服务器优先（响应快，~200ms）
    // 国内 DoH 对 github.com 等核心域名会返回污染 IP，但 IP 验证会过滤
    // CDN 域名 (*.githubusercontent.com) 的解析结果是正确的
    // 海外 DoH 作为兜底：核心域名被污染时，海外 DoH 能返回正确 IP
    private static final String[] DOH_SERVERS = {
            "https://223.5.5.5/dns-query",           // Alidns (国内最快)
            "https://1.12.12.12/dns-query",           // DNSPod
            "https://120.53.53.53/dns-query",         // DNSPod 备用
            "https://1.1.1.1/dns-query",              // Cloudflare (海外)
            "https://8.8.8.8/dns-query",              // Google (海外)
            "https://9.9.9.9/dns-query",              // Quad9 (海外, 不同 Anycast)
    };

    private static final int CONNECT_TIMEOUT_MS = 3000;
    private static final int READ_TIMEOUT_MS = 3000;

    /**
     * GitHub 合法 IPv4 网段（CIDR 前缀）
     * 来源: https://api.github.com/meta
     */
    private static final long[][] GITHUB_IPV4_RANGES = {
            // {网络地址(long), 掩码位数}
            {ip4ToLong(20, 205, 243, 0), 24},    // Azure Singapore
            {ip4ToLong(20, 27, 177, 0), 24},     // Azure
            {ip4ToLong(20, 248, 137, 0), 24},    // Azure
            {ip4ToLong(20, 207, 73, 0), 24},     // Azure
            {ip4ToLong(140, 82, 112, 0), 20},    // GitHub legacy
            {ip4ToLong(143, 55, 64, 0), 20},     // GitHub
            {ip4ToLong(185, 199, 108, 0), 22},   // GitHub Pages/CDN (Fastly)
            {ip4ToLong(192, 30, 252, 0), 22},    // GitHub legacy
            {ip4ToLong(13, 107, 42, 0), 24},     // Microsoft/GitHub
            {ip4ToLong(13, 107, 43, 0), 24},     // Microsoft/GitHub
            {ip4ToLong(4, 208, 26, 0), 24},      // GitHub Actions
    };

    /**
     * GitHub 合法 IPv6 前缀
     */
    private static final String[] GITHUB_IPV6_PREFIXES = {
            "2606:50c0:",    // GitHub Pages CDN
            "2a0a:a440:",    // GitHub
            "2001:4860:",    // Google Cloud (GitHub Actions)
    };

    private DohResolver() {
    }

    /**
     * 设置底层物理网络（由 VPN 服务在启动时调用）。
     * 在 VPN 服务进程中，HTTP 连接需要绑定到物理网络以绕过 VPN 路由。
     * 在 Xposed hook 的目标应用进程中无需设置（DoH 流量不经过 VPN TUN）。
     */
    public static void setNetwork(Network network) {
        sNetwork = network;
    }

    private static long ip4ToLong(int a, int b, int c, int d) {
        return ((long) a << 24) | ((long) b << 16) | ((long) c << 8) | d;
    }

    /**
     * 校验 IPv4 地址是否属于 GitHub 合法网段
     */
    static boolean isGithubIpv4(byte[] addr) {
        if (addr == null || addr.length != 4) return false;
        long ip = ((long) (addr[0] & 0xFF) << 24) | ((long) (addr[1] & 0xFF) << 16)
                | ((long) (addr[2] & 0xFF) << 8) | (addr[3] & 0xFF);
        for (long[] range : GITHUB_IPV4_RANGES) {
            long network = range[0];
            int bits = (int) range[1];
            long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
            if ((ip & mask) == (network & mask)) return true;
        }
        return false;
    }

    /**
     * 校验 IPv6 地址是否属于 GitHub 合法前缀
     */
    static boolean isGithubIpv6(byte[] addr) {
        if (addr == null || addr.length != 16) return false;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%x", ((addr[i] & 0xFF) << 8) | (addr[i + 1] & 0xFF)));
        }
        String full = sb.toString().toLowerCase();
        for (String prefix : GITHUB_IPV6_PREFIXES) {
            if (full.startsWith(prefix)) return true;
        }
        return false;
    }

    /**
     * 通过 DoH 解析域名，同时查询 A (IPv4) 和 AAAA (IPv6) 记录。
     * 依次尝试 DoH 服务器列表，任一成功即返回（快速路径）。
     *
     * @return 解析结果数组，失败返回 null
     */
    public static InetAddress[] resolve(String host) {
        boolean pollutionDetected = false;
        for (String server : DOH_SERVERS) {
            try {
                InetAddress[] result = queryDoh(server, host);
                if (result != null && result.length > 0) {
                    return result;
                }
                if (result != null && result.length == 0) {
                    pollutionDetected = true;
                    Log.w(TAG, "DNS pollution from " + server + " for " + host);
                }
            } catch (Exception e) {
                Log.w(TAG, "DoH query failed with " + server + ": " + e.getMessage());
            }
        }
        if (pollutionDetected) {
            Log.w(TAG, "All DoH servers returned polluted results for " + host);
        }
        return null;
    }

    /**
     * 从所有 DoH 服务器收集去重 IP（慢路径，用于 HostsSyncer 的多 IP 回退）。
     * 不同 DoH 提供商可能返回不同的 Anycast IP，部分 IP 可能被 GFW 封锁。
     *
     * @return 去重后的所有有效 IP，失败返回 null
     */
    public static InetAddress[] resolveAll(String host) {
        List<InetAddress> all = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (String server : DOH_SERVERS) {
            try {
                InetAddress[] result = queryDoh(server, host);
                if (result != null) {
                    for (InetAddress addr : result) {
                        if (seen.add(addr.getHostAddress())) {
                            all.add(addr);
                        }
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "DoH resolveAll failed with " + server + ": " + e.getMessage());
            }
        }

        if (all.isEmpty()) {
            Log.w(TAG, "resolveAll: no valid IPs for " + host);
            return null;
        }
        Log.i(TAG, "resolveAll: " + host + " → " + all.size() + " unique IPs");
        return all.toArray(new InetAddress[0]);
    }

    private static InetAddress[] queryDoh(String server, String host) throws Exception {
        List<InetAddress> addresses = new ArrayList<>();
        boolean serverResponded = false;

        // 查询 A 记录 (IPv4, type=1)
        List<InetAddress> v4 = queryDohType(server, host, 1);
        if (v4 != null) {
            addresses.addAll(v4);
            serverResponded = true;
        }

        // 查询 AAAA 记录 (IPv6, type=28)
        List<InetAddress> v6 = queryDohType(server, host, 28);
        if (v6 != null) {
            addresses.addAll(v6);
            serverResponded = true;
        }

        if (addresses.isEmpty()) {
            // 区分 "服务器无响应" 与 "有响应但 IP 全被过滤(污染)"
            // 返回空数组表示检测到污染，返回 null 表示服务器不可用
            return serverResponded ? new InetAddress[0] : null;
        }
        return addresses.toArray(new InetAddress[0]);
    }

    private static List<InetAddress> queryDohType(String server, String host, int type) throws Exception {
        String urlStr = server + "?name=" + host + "&type=" + (type == 28 ? "AAAA" : "A");

        URL url = new URL(urlStr);
        Network net = sNetwork;
        HttpURLConnection conn;
        if (net != null) {
            conn = (HttpURLConnection) net.openConnection(url);
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/dns-json");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setInstanceFollowRedirects(true);

            int code = conn.getResponseCode();
            if (code != 200) {
                Log.w(TAG, "DoH HTTP " + code + " from " + server);
                return null;
            }

            String json = readStream(conn.getInputStream());
            return parseJsonResponse(json, host);
        } finally {
            conn.disconnect();
        }
    }

    private static List<InetAddress> parseJsonResponse(String json, String host) {
        try {
            JSONObject root = new JSONObject(json);

            // 检查 Status (0 = NOERROR)
            int status = root.optInt("Status", -1);
            if (status != 0) return null;

            JSONArray answers = root.optJSONArray("Answer");
            if (answers == null) return null;

            List<InetAddress> result = new ArrayList<>();
            for (int i = 0; i < answers.length(); i++) {
                JSONObject answer = answers.getJSONObject(i);
                int type = answer.getInt("type");
                // type 1 = A, type 28 = AAAA, type 5 = CNAME (skip)
                if (type != 1 && type != 28) continue;

                String data = answer.getString("data");
                try {
                    byte[] addrBytes = parseIpAddress(data);
                    if (addrBytes == null) continue;

                    // 校验 IP 是否属于 GitHub 合法网段，过滤 DNS 污染
                    if (addrBytes.length == 4 && !isGithubIpv4(addrBytes)) {
                        Log.w(TAG, "Filtered non-GitHub IPv4: " + data);
                        continue;
                    }
                    if (addrBytes.length == 16 && !isGithubIpv6(addrBytes)) {
                        Log.w(TAG, "Filtered non-GitHub IPv6: " + data);
                        continue;
                    }

                    result.add(InetAddress.getByAddress(host, addrBytes));
                } catch (Exception e) {
                    Log.w(TAG, "Failed to parse IP: " + data);
                }
            }
            return result;
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse DoH JSON: " + e.getMessage());
            return null;
        }
    }

    /**
     * 将 IP 字符串解析为字节数组，支持 IPv4 和 IPv6。
     * 不使用 InetAddress.getByName() 以避免递归 DNS 调用。
     */
    public static byte[] parseIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) return null;

        if (ip.contains(":")) {
            // IPv6
            return parseIpv6(ip);
        } else if (ip.contains(".")) {
            // IPv4
            return parseIpv4(ip);
        }
        return null;
    }

    private static byte[] parseIpv4(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return null;
        byte[] addr = new byte[4];
        for (int i = 0; i < 4; i++) {
            int val = Integer.parseInt(parts[i]);
            if (val < 0 || val > 255) return null;
            addr[i] = (byte) val;
        }
        return addr;
    }

    private static byte[] parseIpv6(String ip) {
        // 处理 :: 缩写
        String[] halves = ip.split("::", -1);
        if (halves.length > 2) return null;

        String[] left = halves[0].isEmpty() ? new String[0] : halves[0].split(":");
        String[] right = halves.length == 2 && !halves[1].isEmpty() ? halves[1].split(":") : new String[0];

        int totalGroups = left.length + right.length;
        if (halves.length == 1 && totalGroups != 8) return null;
        if (halves.length == 2 && totalGroups > 7) return null;

        int missingGroups = 8 - totalGroups;
        byte[] addr = new byte[16];
        int idx = 0;

        for (String part : left) {
            int val = Integer.parseInt(part, 16);
            addr[idx++] = (byte) (val >> 8);
            addr[idx++] = (byte) (val & 0xFF);
        }
        for (int i = 0; i < missingGroups; i++) {
            addr[idx++] = 0;
            addr[idx++] = 0;
        }
        for (String part : right) {
            int val = Integer.parseInt(part, 16);
            addr[idx++] = (byte) (val >> 8);
            addr[idx++] = (byte) (val & 0xFF);
        }
        return addr;
    }

    private static String readStream(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int len;
        while ((len = is.read(buf)) != -1) {
            bos.write(buf, 0, len);
        }
        return bos.toString("UTF-8");
    }
}
