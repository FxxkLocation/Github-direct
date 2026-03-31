package org.xiyu.githubdirect.dns;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * GitHub 域名的 IP 列表，完全由 HostsSyncer 从 github-hosts 同步填充。
 * 不再使用硬编码 IP。
 */
public final class BuiltinIPs {

    private static final Map<String, String[]> IPV4_MAP = new HashMap<>();
    private static final Map<String, String[]> IPV6_MAP = new HashMap<>();

    // 所有 IP 由 HostsSyncer 动态填充，不再硬编码

    private BuiltinIPs() {
    }

    /**
     * 获取域名的内置 IP 列表（IPv4 + IPv6），失败返回 null。
     */
    public static InetAddress[] lookup(String host) {
        if (host == null) return null;
        String lower = host.toLowerCase();

        String[] v4 = IPV4_MAP.get(lower);
        String[] v6 = IPV6_MAP.get(lower);
        if (v4 == null && v6 == null) {
            // 尝试通配符匹配：对 *.githubusercontent.com 域名尝试通用入口
            if (lower.endsWith(".githubusercontent.com")) {
                v4 = IPV4_MAP.get("raw.githubusercontent.com");
                v6 = IPV6_MAP.get("raw.githubusercontent.com");
            }
        }

        if (v4 == null && v6 == null) return null;

        List<InetAddress> result = new ArrayList<>();
        if (v4 != null) {
            for (String ip : v4) {
                try {
                    byte[] addr = DohResolver.parseIpAddress(ip);
                    if (addr != null) {
                        result.add(InetAddress.getByAddress(host, addr));
                    }
                } catch (Exception ignored) {
                }
            }
        }
        if (v6 != null) {
            for (String ip : v6) {
                try {
                    byte[] addr = DohResolver.parseIpAddress(ip);
                    if (addr != null) {
                        result.add(InetAddress.getByAddress(host, addr));
                    }
                } catch (Exception ignored) {
                }
            }
        }

        return result.isEmpty() ? null : result.toArray(new InetAddress[0]);
    }

    /**
     * 动态更新 IP 映射（来自 HostsSyncer）。
     * @param hosts domain → IP 映射
     */
    public static void updateIps(Map<String, String> hosts) {
        for (Map.Entry<String, String> entry : hosts.entrySet()) {
            String domain = entry.getKey();
            String ip = entry.getValue();
            // 更新已有条目的第一个 IP，或新增
            String[] existing = IPV4_MAP.get(domain);
            if (existing != null) {
                existing[0] = ip;
            } else {
                IPV4_MAP.put(domain, new String[]{ip});
            }
        }
    }
}
