# Xposed 入口绝不能被 R8 改名/裁掉：LSPosed 按 java_init.list 的 FQN 反射加载。
-keep class org.xiyu.githubdirect.ModuleMain {
    public <init>(...);
    public void onModuleLoaded(...);
    public void onPackageLoaded(...);
    public void onPackageReady(...);
    public void onSystemServerLoaded(...);
    public void onSystemServerStarting(...);
}
-adaptresourcefilenames META-INF/xposed/java_init.list
-adaptresourcefilecontents META-INF/xposed/java_init.list
-keep class org.xiyu.githubdirect.xposed.** { *; }
-keep class * extends io.github.libxposed.api.XposedModule {
    public <init>(...);
    public void onModuleLoaded(...);
    public void onPackageLoaded(...);
    public void onPackageReady(...);
    public void onSystemServerLoaded(...);
    public void onSystemServerStarting(...);
}

# JNI 使用静态导出符号 Java_org_xiyu_githubdirect_root_OriginalDestination_nativeLookup；
# 类名或方法名被 R8 改写都会让 Release 在首次真实 IP 连接时 UnsatisfiedLinkError。
-keep class org.xiyu.githubdirect.root.OriginalDestination { *; }
-keepattributes RuntimeVisibleAnnotations
-keep @io.github.libxposed.api.annotations.* class * {
    @io.github.libxposed.api.annotations.BeforeInvocation <methods>;
    @io.github.libxposed.api.annotations.AfterInvocation <methods>;
}

# Kotlin
-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
	public static void check*(...);
	public static void throw*(...);
}
-assumenosideeffects class java.util.Objects {
    public static ** requireNonNull(...);
}

# Strip debug log
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

# Obfuscation（ModuleMain 已 -keep，不会被打进默认包）
-repackageclasses
-allowaccessmodification

# Ignore missing annotations
-dontwarn androidx.annotation.**
# 由 root app_process 通过稳定类名启动；R8 不得删除或改名 main 入口。
-keep class org.xiyu.githubdirect.root.OplusHansRootLease {
    public static void main(java.lang.String[]);
}

# Root helper 通过稳定类名由 app_process 启动，并在降权后调用平台证书存储。
-keep class org.xiyu.githubdirect.root.AndroidKeyChainRootHelper {
    public static void main(java.lang.String[]);
}

# Edge 138+ Android CA policy helper; stable name is invoked by root app_process.
-keep class org.xiyu.githubdirect.root.BrowserPolicyRootHelper {
    public static void main(java.lang.String[]);
}
