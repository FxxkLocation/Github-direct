package org.xiyu.githubdirect;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.PackageLoadedParam;

import org.xiyu.githubdirect.core.dns.IpAddresses;
import org.xiyu.githubdirect.core.dns.EndpointCache;
import org.xiyu.githubdirect.core.dns.EndpointResolver;
import org.xiyu.githubdirect.core.net.RelayIpTable;
import org.xiyu.githubdirect.core.rules.RuleRegistry;
import org.xiyu.githubdirect.data.DirectEngine;
import org.xiyu.githubdirect.xposed.XposedDnsInterceptor;

/**
 * Xposed 模块入口（FQN 保持 org.xiyu.githubdirect.ModuleMain，java_init.list 引用）。
 * <p>
 * 拦截 InetAddress.getAllByName / getByName：
 * - 未命中/解析失败 → chain.proceed()（Xposed 下解析照常）
 * - NXDOMAIN 屏蔽域 → getAllByName 返回空数组；getByName 抛 UnknownHostException
 * - 其余命中 → 真实 IP（XposedDnsInterceptor，CLEAN_DNS 语义 + EndpointCache）
 * <p>
 * 引擎惰性初始化：反射 ActivityThread.currentApplication + createPackageContext
 * 读取模块 assets（target 进程无模块类加载器）。
 */
public class ModuleMain extends XposedModule {

    private static final String TAG = "GithubDirect";

    private volatile XposedDnsInterceptor interceptor;

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
                + ", hooking DNS...");

        if (!param.isFirstPackage()) return;

        try {
            hookGetAllByName();
            hookGetByName();
            log(Log.INFO, TAG, "DNS hooks installed successfully");
            // 后台预热拦截器（规则加载/索引构建），避免首次 DNS 查询的同步初始化延迟
            Thread warmup = new Thread(() -> {
                try {
                    getInterceptor();
                    log(Log.INFO, TAG, "Interceptor warmup done");
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "Interceptor warmup failed: " + t.getMessage());
                }
            }, "Direct-Warmup");
            warmup.setDaemon(true);
            warmup.start();
        } catch (Exception e) {
            log(Log.ERROR, TAG, "Failed to install DNS hooks: " + e.getMessage());
        }
    }

    private void hookGetAllByName() throws NoSuchMethodException {
        Method getAllByName = InetAddress.class.getMethod("getAllByName", String.class);

        hook(getAllByName).intercept(chain -> {
            String host = (String) chain.getArg(0);
            XposedDnsInterceptor interceptor = getInterceptor();
            if (host == null || interceptor == null) {
                return chain.proceed();
            }

            List<String> ips = interceptor.resolve(host);
            if (ips == null) {
                return chain.proceed(); // 未命中/解析失败 → 系统 DNS
            }
            if (ips.isEmpty()) {
                log(Log.WARN, TAG, "屏蔽域: " + host);
                return new InetAddress[0]; // NXDOMAIN 语义：空数组
            }

            InetAddress[] addrs = new InetAddress[ips.size()];
            for (int i = 0; i < ips.size(); i++) {
                byte[] raw = IpAddresses.parseIpAddress(ips.get(i));
                if (raw != null) {
                    addrs[i] = InetAddress.getByAddress(host, raw);
                }
            }
            log(Log.DEBUG, TAG, "DNS intercepted: " + host + " -> " + ips.size() + " addrs");
            return addrs;
        });
    }

    private void hookGetByName() throws NoSuchMethodException {
        Method getByName = InetAddress.class.getMethod("getByName", String.class);

        hook(getByName).intercept(chain -> {
            String host = (String) chain.getArg(0);
            XposedDnsInterceptor interceptor = getInterceptor();
            if (host == null || interceptor == null) {
                return chain.proceed();
            }

            List<String> ips = interceptor.resolve(host);
            if (ips == null) {
                return chain.proceed();
            }
            if (ips.isEmpty()) {
                throw new UnknownHostException("blocked: " + host); // NXDOMAIN 语义
            }
            byte[] raw = IpAddresses.parseIpAddress(ips.get(0));
            if (raw == null) {
                return chain.proceed();
            }
            return InetAddress.getByAddress(host, raw);
        });
    }

    /**
     * 惰性获取拦截器：反射 ActivityThread.currentApplication 拿宿主进程 context，
     * 再 createPackageContext 读取模块 assets（规则目录）。
     */
    private XposedDnsInterceptor getInterceptor() {
        if (interceptor != null) return interceptor;
        synchronized (ModuleMain.class) {
            if (interceptor != null) return interceptor;
            try {
                Context ctx = getModuleContext();
                if (ctx == null) return null;
                if (!DirectEngine.ensureInit(ctx, false)) {
                    log(Log.WARN, TAG, "引擎初始化失败，DNS 拦截不可用");
                    return null;
                }
                RuleRegistry registry = DirectEngine.registry();
                EndpointResolver resolver = DirectEngine.resolver();
                EndpointCache cache = DirectEngine.cache();
                RelayIpTable table = DirectEngine.relayTable();
                if (registry == null || resolver == null || cache == null || table == null) {
                    return null;
                }
                interceptor = new XposedDnsInterceptor(registry, resolver, cache, table);
            } catch (Throwable t) {
                log(Log.WARN, TAG, "初始化拦截器失败: " + t.getMessage());
            }
        }
        return interceptor;
    }

    /** target 进程无模块 ClassLoader：反射 ActivityThread 拿 context。 */
    private Context getModuleContext() {
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method currentApp = atClass.getMethod("currentApplication");
            Application app = (Application) currentApp.invoke(null);
            if (app == null) return null;
            return app.createPackageContext("org.xiyu.githubdirect", 0);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "获取模块 context 失败: " + t.getMessage());
            return null;
        }
    }
}
