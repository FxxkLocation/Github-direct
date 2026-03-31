package org.xiyu.githubdirect.vpn;

import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * 虚拟 IP 映射：为 SNI 被封锁的 GitHub 域名分配虚拟 IP（10.0.0.x），
 * 并映射到真实可达的 GitHub IP。
 * <p>
 * VPN 路由 10.0.0.0/24 到 TUN，TCP 流量经 TcpRelay 中继到真实 IP。
 */
public class VirtualIpMap {

    // 虚拟 IP → 真实 IP
    private static final Map<String, String> VIRTUAL_TO_REAL = new HashMap<>();
    // 域名 → 虚拟 IP
    private static final Map<String, String> DOMAIN_TO_VIRTUAL = new HashMap<>();
    // 域名 → 真实 IP（直达，无需 TCP relay）
    private static final Map<String, String> DOMAIN_TO_DIRECT = new HashMap<>();

    // SNI 被封锁，需要 TCP relay + TLS record 分片
    // 虚拟 IP 分配（真实 IP 由 HostsSyncer 从 github-hosts 同步）
    private static final String[][] SNI_BLOCKED = {
            {"github.com", "10.0.0.10"},
            {"api.github.com", "10.0.0.11"},
            {"gist.github.com", "10.0.0.12"},
            {"codeload.github.com", "10.0.0.13"},
            {"alive.github.com", "10.0.0.14"},
            {"central.github.com", "10.0.0.15"},
    };

    // CDN 域名：不再硬编码，由 HostsSyncer 同步填充

    static {
        for (String[] entry : SNI_BLOCKED) {
            DOMAIN_TO_VIRTUAL.put(entry[0], entry[1]);
            // VIRTUAL_TO_REAL 留空，由 HostsSyncer 填充
        }
    }

    /**
     * 域名 → 虚拟 IP（SNI 被封锁的域名）。
     *
     * @return 虚拟 IP 字符串，或 null（不需要 relay）
     */
    public static String getVirtualIp(String domain) {
        return DOMAIN_TO_VIRTUAL.get(domain.toLowerCase());
    }

    /**
     * 域名 → 直连 IP（无 SNI 封锁的域名）。
     *
     * @return 真实 IP 字符串，或 null
     */
    public static String getDirectIp(String domain) {
        String lower = domain.toLowerCase();
        String ip = DOMAIN_TO_DIRECT.get(lower);
        if (ip != null) return ip;
        // 通配符匹配：查找同后缀的已有条目
        if (lower.endsWith(".githubusercontent.com")) {
            String ref = DOMAIN_TO_DIRECT.get("raw.githubusercontent.com");
            return ref; // 可能为 null（同步前）
        }
        if (lower.endsWith(".github.io")) {
            String ref = DOMAIN_TO_DIRECT.get("github.io");
            return ref;
        }
        return null;
    }

    /**
     * 虚拟 IP → 真实 IP 的 4 字节数组。
     *
     * @return 4 字节数组，或 null
     */
    public static byte[] getRealIp(byte[] virtualIp) {
        String vipStr = (virtualIp[0] & 0xFF) + "." + (virtualIp[1] & 0xFF) + "."
                + (virtualIp[2] & 0xFF) + "." + (virtualIp[3] & 0xFF);
        String realStr = VIRTUAL_TO_REAL.get(vipStr);
        if (realStr == null) return null;
        return parseIpv4(realStr);
    }

    /**
     * 判断一个 IP 是否是虚拟 IP（10.0.0.x，x>=10）。
     */
    public static boolean isVirtualIp(byte[] ip) {
        return ip.length >= 4
                && (ip[0] & 0xFF) == 10
                && (ip[1] & 0xFF) == 0
                && (ip[2] & 0xFF) == 0
                && (ip[3] & 0xFF) >= 10;
    }

    /**
     * 域名是否需要 SNI bypass（TCP relay）。
     */
    public static boolean needsRelay(String domain) {
        return DOMAIN_TO_VIRTUAL.containsKey(domain.toLowerCase());
    }

    /**
     * 获取 relay 域名当前的真实 IP（如果已设置）。
     *
     * @return 真实 IP 字符串，或 null（尚未同步）
     */
    public static String getCurrentRelayIp(String domain) {
        String virtualIp = DOMAIN_TO_VIRTUAL.get(domain.toLowerCase());
        if (virtualIp == null) return null;
        return VIRTUAL_TO_REAL.get(virtualIp);
    }

    /**
     * 动态更新 IP 映射（来自 HostsSyncer）。
     * 对于 SNI_BLOCKED 域名：更新 虚拟IP→真实IP 映射。
     * 对于 DIRECT 域名：更新 域名→直连IP 映射。
     *
     * @param hosts domain → IP 映射
     */
    public static void updateIps(Map<String, String> hosts) {
        int updated = 0;
        for (Map.Entry<String, String> entry : hosts.entrySet()) {
            String domain = entry.getKey();
            String newIp = entry.getValue();

            // SNI 被封锁的域名 → 更新 虚拟IP→真实IP
            String virtualIp = DOMAIN_TO_VIRTUAL.get(domain);
            if (virtualIp != null) {
                String oldIp = VIRTUAL_TO_REAL.get(virtualIp);
                if (!newIp.equals(oldIp)) {
                    VIRTUAL_TO_REAL.put(virtualIp, newIp);
                    Log.i("GithubDirect", "IP 更新 [relay]: " + domain + " " + oldIp + " → " + newIp);
                    updated++;
                }
                continue;
            }

            // 直连域名 → 更新 域名→直连IP
            if (DOMAIN_TO_DIRECT.containsKey(domain)) {
                String oldIp = DOMAIN_TO_DIRECT.get(domain);
                if (!newIp.equals(oldIp)) {
                    DOMAIN_TO_DIRECT.put(domain, newIp);
                    Log.i("GithubDirect", "IP 更新 [direct]: " + domain + " " + oldIp + " → " + newIp);
                    updated++;
                }
            } else {
                // 新域名 → 加入直连映射
                DOMAIN_TO_DIRECT.put(domain, newIp);
                updated++;
            }
        }
        if (updated > 0) {
            Log.i("GithubDirect", "IP 映射更新完成: " + updated + " 条变更");
        }
    }

    private static byte[] parseIpv4(String ip) {
        String[] parts = ip.split("\\.");
        return new byte[]{
                (byte) Integer.parseInt(parts[0]),
                (byte) Integer.parseInt(parts[1]),
                (byte) Integer.parseInt(parts[2]),
                (byte) Integer.parseInt(parts[3])
        };
    }
}
