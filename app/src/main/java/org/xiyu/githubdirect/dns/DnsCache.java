package org.xiyu.githubdirect.dns;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;

public final class DnsCache {

    private static final long DEFAULT_TTL_MS = 10 * 60 * 1000L; // 10 minutes
    private static final int MAX_SIZE = 128;

    private static final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    private DnsCache() {
    }

    public static InetAddress[] get(String host) {
        CacheEntry entry = cache.get(host.toLowerCase());
        if (entry == null) return null;
        if (System.currentTimeMillis() > entry.expireTime) {
            cache.remove(host.toLowerCase());
            return null;
        }
        return entry.addresses;
    }

    public static void put(String host, InetAddress[] addresses) {
        put(host, addresses, DEFAULT_TTL_MS);
    }

    public static void put(String host, InetAddress[] addresses, long ttlMs) {
        if (addresses == null || addresses.length == 0) return;
        if (cache.size() >= MAX_SIZE) {
            evictExpired();
        }
        cache.put(host.toLowerCase(), new CacheEntry(addresses, System.currentTimeMillis() + ttlMs));
    }

    public static void clear() {
        cache.clear();
    }

    public static int size() {
        return cache.size();
    }

    private static void evictExpired() {
        long now = System.currentTimeMillis();
        cache.entrySet().removeIf(e -> now > e.getValue().expireTime);
    }

    private static final class CacheEntry {
        final InetAddress[] addresses;
        final long expireTime;

        CacheEntry(InetAddress[] addresses, long expireTime) {
            this.addresses = addresses;
            this.expireTime = expireTime;
        }
    }
}
