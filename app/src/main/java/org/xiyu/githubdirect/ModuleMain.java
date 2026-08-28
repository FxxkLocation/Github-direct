package org.xiyu.githubdirect;

import android.annotation.TargetApi;
import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.DnsResolver;
import android.net.Network;
import android.os.CancellationSignal;
import android.os.SystemClock;
import android.os.Build;
import android.util.Log;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import io.github.libxposed.api.XposedInterface.ExceptionMode;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.PackageLoadedParam;

import org.xiyu.githubdirect.core.data.SettingsStore;
import org.xiyu.githubdirect.core.data.HookHeartbeat;
import org.xiyu.githubdirect.core.dns.EndpointCache;
import org.xiyu.githubdirect.core.dns.IpAddresses;
import org.xiyu.githubdirect.core.dns.ResolutionDecision;
import org.xiyu.githubdirect.core.net.RelayIpTable;
import org.xiyu.githubdirect.core.rules.RuleRegistry;
import org.xiyu.githubdirect.data.AndroidSettingsStore;
import org.xiyu.githubdirect.data.DirectEngine;
import org.xiyu.githubdirect.data.HookHeartbeatIpc;
import org.xiyu.githubdirect.xposed.XposedDnsInterceptor;

/**
 * 现代 libxposed 模块入口。
 *
 * Hook 本身严格走内存快照：没有 DoH、TCP 探测、Future 等待或主线程阻塞。缓存未就绪、
 * 类型不支持、内部异常时一律调用原实现，避免把模块故障扩散到目标应用。
 */
public final class ModuleMain extends XposedModule {

    private static final String TAG = "GithubDirect";
    private static final String MODULE_PKG = "org.xiyu.githubdirect";
    private static final int DNS_RCODE_NXDOMAIN = 3;

    private final AtomicBoolean hooksInstalled = new AtomicBoolean(false);
    private final AtomicBoolean attachHookInstalled = new AtomicBoolean(false);
    private final AtomicBoolean interceptorReadyReported = new AtomicBoolean(false);
    private final AtomicBoolean startupHeartbeatScheduled = new AtomicBoolean(false);
    private final AtomicLong heartbeatDueAt = new AtomicLong(0);
    private final AtomicLong hookHits = new AtomicLong(0);
    private final ScheduledExecutorService heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "GHD-HookHeartbeat");
        thread.setDaemon(true);
        return thread;
    });
    private volatile Context hostContext;
    private volatile XposedDnsInterceptor interceptor;
    private volatile SettingsStore remoteSettingsStore;
    private volatile String loadedPackage = "unknown";
    private volatile String loadedProcess = "unknown";

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        loadedProcess = param.getProcessName();
        // 此阶段 ActivityThread.currentApplication 通常尚不可用，禁止做 context 初始化或网络预热。
        log(Log.INFO, TAG, "Module loaded: process=" + param.getProcessName()
                + ", api=" + getApiVersion() + ", framework=" + getFrameworkName()
                + " " + getFrameworkVersion() + " (" + getFrameworkVersionCode() + ")");
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!param.isFirstPackage()) return;
        loadedPackage = param.getPackageName();
        log(Log.INFO, TAG, "First package loaded: " + param.getPackageName());
        installApplicationAttachHook();
        installDnsHooks();
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!param.isFirstPackage()) return;
        installDnsHooks();
        log(Log.INFO, TAG, "Package ready: " + param.getPackageName()
                + ", interceptor=" + (interceptor != null ? "ready" : "pending-application-attach"));
    }

    /** Application.attach 是最早且稳定的宿主 Context 获取点。 */
    private void installApplicationAttachHook() {
        if (!attachHookInstalled.compareAndSet(false, true)) return;
        try {
            Method attach = Application.class.getDeclaredMethod("attach", Context.class);
            attach.setAccessible(true);
            hook(attach)
                    .setExceptionMode(ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        Object arg = chain.getArg(0);
                        if (arg instanceof Context) captureHostContext((Context) arg);
                        Object result = chain.proceed();
                        // 某些 ROM 在 attach 前限制 package context；原方法完成后再安全重试一次。
                        if (interceptor == null && arg instanceof Context) {
                            captureHostContext((Context) arg);
                        }
                        return result;
                    });
        } catch (Throwable t) {
            attachHookInstalled.set(false);
            log(Log.WARN, TAG, "Application.attach hook unavailable", t);
        }
    }

    private void installDnsHooks() {
        if (!hooksInstalled.compareAndSet(false, true)) return;
        int installed = 0;
        installed += hookInetAddressGetAllByName() ? 1 : 0;
        installed += hookInetAddressGetByName() ? 1 : 0;
        installed += hookNetworkGetAllByName() ? 1 : 0;
        installed += hookNetworkGetByName() ? 1 : 0;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            installed += hookDnsResolverTypedQuery() ? 1 : 0;
            installed += hookDnsResolverAddressQuery() ? 1 : 0;
        }
        if (installed == 0) hooksInstalled.set(false);
        log(installed > 0 ? Log.INFO : Log.ERROR, TAG, "DNS hooks installed=" + installed + "/6");
    }

    private boolean hookInetAddressGetAllByName() {
        try {
            Method method = InetAddress.class.getMethod("getAllByName", String.class);
            hook(method).setExceptionMode(ExceptionMode.PROTECTIVE).intercept(chain -> {
                String host = (String) chain.getArg(0);
                ResolutionDecision decision = decideSafe(host);
                if (decision instanceof ResolutionDecision.Passthrough) return chain.proceed();
                if (decision instanceof ResolutionDecision.Nxdomain) {
                    throw new UnknownHostException("blocked by GitHub-direct: " + host);
                }
                InetAddress[] addresses = toAddresses(host,
                        ((ResolutionDecision.Addresses) decision).getAddresses(), 0);
                return addresses.length == 0 ? chain.proceed() : addresses;
            });
            return true;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "InetAddress.getAllByName hook failed", t);
            return false;
        }
    }

    private boolean hookInetAddressGetByName() {
        try {
            Method method = InetAddress.class.getMethod("getByName", String.class);
            hook(method).setExceptionMode(ExceptionMode.PROTECTIVE).intercept(chain -> {
                String host = (String) chain.getArg(0);
                ResolutionDecision decision = decideSafe(host);
                if (decision instanceof ResolutionDecision.Passthrough) return chain.proceed();
                if (decision instanceof ResolutionDecision.Nxdomain) {
                    throw new UnknownHostException("blocked by GitHub-direct: " + host);
                }
                InetAddress[] addresses = toAddresses(host,
                        ((ResolutionDecision.Addresses) decision).getAddresses(), 0);
                return addresses.length == 0 ? chain.proceed() : addresses[0];
            });
            return true;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "InetAddress.getByName hook failed", t);
            return false;
        }
    }

    private boolean hookNetworkGetAllByName() {
        try {
            Method method = Network.class.getMethod("getAllByName", String.class);
            hook(method).setExceptionMode(ExceptionMode.PROTECTIVE).intercept(chain -> {
                String host = (String) chain.getArg(0);
                ResolutionDecision decision = decideSafe(host);
                if (decision instanceof ResolutionDecision.Passthrough) return chain.proceed();
                if (decision instanceof ResolutionDecision.Nxdomain) {
                    throw new UnknownHostException("blocked by GitHub-direct: " + host);
                }
                InetAddress[] addresses = toAddresses(host,
                        ((ResolutionDecision.Addresses) decision).getAddresses(), 0);
                return addresses.length == 0 ? chain.proceed() : addresses;
            });
            return true;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Network.getAllByName hook failed", t);
            return false;
        }
    }

    private boolean hookNetworkGetByName() {
        try {
            Method method = Network.class.getMethod("getByName", String.class);
            hook(method).setExceptionMode(ExceptionMode.PROTECTIVE).intercept(chain -> {
                String host = (String) chain.getArg(0);
                ResolutionDecision decision = decideSafe(host);
                if (decision instanceof ResolutionDecision.Passthrough) return chain.proceed();
                if (decision instanceof ResolutionDecision.Nxdomain) {
                    throw new UnknownHostException("blocked by GitHub-direct: " + host);
                }
                InetAddress[] addresses = toAddresses(host,
                        ((ResolutionDecision.Addresses) decision).getAddresses(), 0);
                return addresses.length == 0 ? chain.proceed() : addresses[0];
            });
            return true;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Network.getByName hook failed", t);
            return false;
        }
    }

    /** query(Network, name, nsType, flags, Executor, CancellationSignal, Callback<List<InetAddress>>) */
    @TargetApi(Build.VERSION_CODES.Q)
    private boolean hookDnsResolverTypedQuery() {
        try {
            Method method = DnsResolver.class.getMethod(
                    "query", Network.class, String.class, int.class, int.class,
                    Executor.class, CancellationSignal.class, DnsResolver.Callback.class);
            hook(method).setExceptionMode(ExceptionMode.PROTECTIVE).intercept(chain -> {
                int qtype = (Integer) chain.getArg(2);
                if (qtype != DnsResolver.TYPE_A && qtype != DnsResolver.TYPE_AAAA) {
                    return chain.proceed();
                }
                return interceptDnsResolver(
                        chain.getArg(1), qtype, chain.getArg(4), chain.getArg(5), chain.getArg(6),
                        chain::proceed);
            });
            return true;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "DnsResolver typed query hook failed", t);
            return false;
        }
    }

    /** query(Network, name, flags, Executor, CancellationSignal, Callback<List<InetAddress>>) */
    @TargetApi(Build.VERSION_CODES.Q)
    private boolean hookDnsResolverAddressQuery() {
        try {
            Method method = DnsResolver.class.getMethod(
                    "query", Network.class, String.class, int.class,
                    Executor.class, CancellationSignal.class, DnsResolver.Callback.class);
            hook(method).setExceptionMode(ExceptionMode.PROTECTIVE).intercept(chain ->
                    interceptDnsResolver(
                            chain.getArg(1), 0, chain.getArg(3), chain.getArg(4), chain.getArg(5),
                            chain::proceed));
            return true;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "DnsResolver address query hook failed", t);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    @TargetApi(Build.VERSION_CODES.Q)
    private Object interceptDnsResolver(
            Object hostArg,
            int qtype,
            Object executorArg,
            Object cancellationArg,
            Object callbackArg,
            Proceed original) throws Throwable {
        if (!(hostArg instanceof String)
                || !(executorArg instanceof Executor)
                || !(callbackArg instanceof DnsResolver.Callback)) {
            return original.call();
        }
        CancellationSignal cancellation = cancellationArg instanceof CancellationSignal
                ? (CancellationSignal) cancellationArg : null;
        if (cancellation != null && cancellation.isCanceled()) return original.call();

        String host = (String) hostArg;
        ResolutionDecision decision = decideSafe(host);
        boolean suppressAaaa = qtype == DnsResolver.TYPE_AAAA && shouldSuppressAaaaSafe(host);
        if (suppressAaaa && decision instanceof ResolutionDecision.Passthrough) {
            maybeRecordHeartbeat();
        }
        if (decision instanceof ResolutionDecision.Passthrough && !suppressAaaa) return original.call();

        final List<InetAddress> answer;
        final int rcode;
        if (decision instanceof ResolutionDecision.Nxdomain) {
            answer = Collections.emptyList();
            rcode = DNS_RCODE_NXDOMAIN;
        } else if (suppressAaaa) {
            // 名字存在但没有 AAAA：NOERROR/NODATA，绝不能伪装成 NXDOMAIN。
            answer = Collections.emptyList();
            rcode = 0;
        } else {
            int family = qtype == DnsResolver.TYPE_A ? 4
                    : (qtype == DnsResolver.TYPE_AAAA ? 16 : 0);
            InetAddress[] parsed = toAddresses(host,
                    ((ResolutionDecision.Addresses) decision).getAddresses(), family);
            if (parsed.length == 0) return original.call();
            answer = List.of(parsed);
            rcode = 0;
        }

        Executor executor = (Executor) executorArg;
        DnsResolver.Callback<List<InetAddress>> callback =
                (DnsResolver.Callback<List<InetAddress>>) callbackArg;
        try {
            executor.execute(() -> {
                if (cancellation == null || !cancellation.isCanceled()) {
                    callback.onAnswer(answer, rcode);
                }
            });
            return null;
        } catch (Throwable schedulingFailure) {
            return original.call();
        }
    }

    private boolean shouldSuppressAaaaSafe(String host) {
        if (host == null) return false;
        try {
            XposedDnsInterceptor current = getInterceptor();
            return current != null && current.shouldSuppressAaaa(host);
        } catch (Throwable t) {
            return false;
        }
    }

    private ResolutionDecision decideSafe(String host) {
        if (host == null) return ResolutionDecision.Passthrough.INSTANCE;
        try {
            XposedDnsInterceptor current = getInterceptor();
            ResolutionDecision decision = current == null
                    ? ResolutionDecision.Passthrough.INSTANCE
                    : current.decide(host);
            if (!(decision instanceof ResolutionDecision.Passthrough)) maybeRecordHeartbeat();
            return decision;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "DNS decision failed for " + host, t);
            return ResolutionDecision.Passthrough.INSTANCE;
        }
    }

    /** 热路径只做原子计数和一次 daemon executor 投递；远程偏好写入不阻塞宿主 DNS 调用。 */
    private void maybeRecordHeartbeat() {
        hookHits.incrementAndGet();
        scheduleHeartbeat();
    }

    /**
     * 初始化成功也写入一次运行证明。Chromium 常使用原生 DNS；hits=0 表示模块已初始化，
     * 但尚未观察到 Java/DnsResolver 规则命中，不能误报为 Hook 未加载。
     */
    private void scheduleStartupHeartbeat() {
        if (!startupHeartbeatScheduled.compareAndSet(false, true)) return;
        scheduleHeartbeat();
    }

    private void scheduleHeartbeat() {
        long nowElapsed = SystemClock.elapsedRealtime();
        long due = heartbeatDueAt.get();
        if (nowElapsed < due) return;
        long jitter = Math.floorMod(loadedPackage.hashCode(), 5001);
        if (!heartbeatDueAt.compareAndSet(due, nowElapsed + HEARTBEAT_BASE_MS + jitter)) return;
        try {
            heartbeatExecutor.execute(() -> writeHeartbeat(HEARTBEAT_RETRY_COUNT));
        } catch (Throwable ignored) {
        }
    }

    private void writeHeartbeat(int retriesRemaining) {
        try {
            SettingsStore store = remoteSettingsStore;
            if (store == null) throw new IllegalStateException("remote settings unavailable");
            String token = store.ensureHookHeartbeatToken();
            if (token == null || token.isEmpty()) {
                throw new IllegalStateException("heartbeat token unavailable");
            }
            long hits = hookHits.get();
            Context context = hostContext;
            if (context == null || !HookHeartbeatIpc.report(context, new HookHeartbeat(
                    loadedPackage,
                    loadedProcess,
                    System.currentTimeMillis(),
                    DirectEngine.routeSnapshot().getGeneration(),
                    getFrameworkName() + " " + getFrameworkVersion()
                            + " (" + getFrameworkVersionCode() + ")",
                    getApiVersion(),
                    hits,
                    token))) {
                throw new IllegalStateException("heartbeat IPC rejected");
            }
        } catch (Throwable t) {
            if (retriesRemaining > 0) {
                try {
                    heartbeatExecutor.schedule(
                            () -> writeHeartbeat(retriesRemaining - 1),
                            HEARTBEAT_RETRY_MS,
                            TimeUnit.MILLISECONDS);
                    return;
                } catch (Throwable ignored) {
                }
            }
            // 心跳永远不能影响目标应用，但最终失败必须留下一条可诊断记录。
            log(Log.WARN, TAG, "Hook heartbeat write failed", t);
        }
    }

    private static InetAddress[] toAddresses(String host, List<String> ips, int familyBytes)
            throws UnknownHostException {
        ArrayList<InetAddress> list = new ArrayList<>(ips.size());
        for (String ip : ips) {
            byte[] raw = IpAddresses.parseIpAddress(ip);
            if (raw != null && (familyBytes == 0 || raw.length == familyBytes)) {
                list.add(InetAddress.getByAddress(host, raw));
            }
        }
        return list.toArray(new InetAddress[0]);
    }

    private void captureHostContext(Context context) {
        Context app = context.getApplicationContext();
        hostContext = app != null ? app : context;
        XposedDnsInterceptor current = getInterceptor(); // 纯本地初始化，预热规则索引和远程快照。
        if (current == null) {
            log(Log.WARN, TAG, "Interceptor still pending after Application.attach; DNS calls will retry");
        }
    }

    private XposedDnsInterceptor getInterceptor() {
        XposedDnsInterceptor current = interceptor;
        if (current != null) return current;
        synchronized (ModuleMain.class) {
            current = interceptor;
            if (current != null) return current;
            Context moduleContext = getModuleContext();
            if (moduleContext == null) return null;
            try {
                SettingsStore remote = remoteSettings();
                // 目标 UID 不能读取模块私有 SharedPreferences。Remote Preferences 暂不可用时
                // 保护性放行并在后续调用重试，禁止把 null 交给 DirectEngine 后误走本地存储。
                if (remote == null) return null;
                remoteSettingsStore = remote;
                if (!DirectEngine.ensureInit(moduleContext, false, remote)) return null;
                RuleRegistry registry = DirectEngine.registry();
                EndpointCache cache = DirectEngine.cache();
                RelayIpTable table = DirectEngine.relayTable();
                if (registry == null || cache == null || table == null) return null;
                current = new XposedDnsInterceptor(registry, cache, table);
                interceptor = current;
                reportInterceptorReady();
                return current;
            } catch (Throwable t) {
                log(Log.WARN, TAG, "Interceptor initialization failed", t);
                return null;
            }
        }
    }

    private void reportInterceptorReady() {
        if (interceptorReadyReported.compareAndSet(false, true)) {
            log(Log.INFO, TAG, "Interceptor ready: package=" + loadedPackage
                    + ", process=" + loadedProcess
                    + ", generation=" + DirectEngine.routeSnapshot().getGeneration());
        }
        scheduleStartupHeartbeat();
    }

    private SettingsStore remoteSettings() {
        try {
            SharedPreferences prefs = getRemotePreferences(AndroidSettingsStore.PREFS_NAME);
            return new AndroidSettingsStore(prefs);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Remote preferences unavailable; DNS hook fails open", t);
            return null;
        }
    }

    private Context getModuleContext() {
        Context host = hostContext;
        if (host == null) return null;
        String packageName = MODULE_PKG;
        try {
            packageName = getModuleApplicationInfo().packageName;
        } catch (Throwable ignored) {
        }
        try {
            return host.createPackageContext(packageName, Context.CONTEXT_IGNORE_SECURITY);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Module context unavailable", t);
            return null;
        }
    }

    @FunctionalInterface
    private interface Proceed {
        Object call() throws Throwable;
    }

    private static final long HEARTBEAT_BASE_MS = 20_000L;
    private static final long HEARTBEAT_RETRY_MS = 2_000L;
    private static final int HEARTBEAT_RETRY_COUNT = 5;
}
