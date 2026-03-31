package org.xiyu.githubdirect;

import android.util.Log;

import java.lang.reflect.Method;
import java.net.InetAddress;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

import org.xiyu.githubdirect.dns.BuiltinIPs;
import org.xiyu.githubdirect.dns.DnsCache;
import org.xiyu.githubdirect.dns.DohResolver;
import org.xiyu.githubdirect.dns.GithubDomains;

public class ModuleMain extends XposedModule {

    private static final String TAG = "GithubDirect";

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "Module loaded in process: " + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        log(Log.INFO, TAG, "Package loaded: " + param.getPackageName()
                + ", classloader: " + param.getDefaultClassLoader());
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        log(Log.INFO, TAG, "Package ready: " + param.getPackageName()
                + ", hooking DNS for GitHub domains...");

        if (!param.isFirstPackage()) return;

        try {
            hookGetAllByName();
            hookGetByName();
            log(Log.INFO, TAG, "DNS hooks installed successfully");
        } catch (Exception e) {
            log(Log.ERROR, TAG, "Failed to install DNS hooks: " + e.getMessage());
        }
    }

    private void hookGetAllByName() throws NoSuchMethodException {
        Method getAllByName = InetAddress.class.getMethod("getAllByName", String.class);

        hook(getAllByName).intercept(chain -> {
            String host = (String) chain.getArg(0);
            if (host == null || !GithubDomains.isGithubDomain(host)) {
                return chain.proceed();
            }

            log(Log.DEBUG, TAG, "Intercepting DNS for: " + host);

            // 1. 查缓存
            InetAddress[] cached = DnsCache.get(host);
            if (cached != null) {
                log(Log.DEBUG, TAG, "Cache hit for " + host + " (" + cached.length + " addresses)");
                return cached;
            }

            // 2. DoH 解析
            try {
                InetAddress[] dohResult = DohResolver.resolve(host);
                if (dohResult != null && dohResult.length > 0) {
                    DnsCache.put(host, dohResult);
                    log(Log.INFO, TAG, "DoH resolved " + host + " -> " + formatAddresses(dohResult));
                    return dohResult;
                }
            } catch (Exception e) {
                log(Log.WARN, TAG, "DoH failed for " + host + ": " + e.getMessage());
            }

            // 3. 内置 IP 兜底
            InetAddress[] builtinResult = BuiltinIPs.lookup(host);
            if (builtinResult != null && builtinResult.length > 0) {
                DnsCache.put(host, builtinResult, 5 * 60 * 1000L); // 内置 IP 缓存 5 分钟
                log(Log.INFO, TAG, "Builtin IP for " + host + " -> " + formatAddresses(builtinResult));
                return builtinResult;
            }

            // 4. 全部失败，回退到系统 DNS
            log(Log.WARN, TAG, "All resolvers failed for " + host + ", falling back to system DNS");
            return chain.proceed();
        });
    }

    private void hookGetByName() throws NoSuchMethodException {
        Method getByName = InetAddress.class.getMethod("getByName", String.class);

        hook(getByName).intercept(chain -> {
            String host = (String) chain.getArg(0);
            if (host == null || !GithubDomains.isGithubDomain(host)) {
                return chain.proceed();
            }

            // 复用 getAllByName 的缓存逻辑
            InetAddress[] cached = DnsCache.get(host);
            if (cached != null && cached.length > 0) {
                return cached[0];
            }

            // DoH
            try {
                InetAddress[] dohResult = DohResolver.resolve(host);
                if (dohResult != null && dohResult.length > 0) {
                    DnsCache.put(host, dohResult);
                    return dohResult[0];
                }
            } catch (Exception ignored) {
            }

            // 内置 IP
            InetAddress[] builtinResult = BuiltinIPs.lookup(host);
            if (builtinResult != null && builtinResult.length > 0) {
                DnsCache.put(host, builtinResult, 5 * 60 * 1000L);
                return builtinResult[0];
            }

            return chain.proceed();
        });
    }

    private static String formatAddresses(InetAddress[] addrs) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < addrs.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(addrs[i].getHostAddress());
        }
        sb.append("]");
        return sb.toString();
    }
}
