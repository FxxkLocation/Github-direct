import java.util.zip.ZipFile
import java.util.zip.ZipEntry
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Properties
import java.util.concurrent.TimeUnit
import java.security.MessageDigest

plugins {
    alias(libs.plugins.agp.app)
}

android {
    namespace = "org.xiyu.githubdirect"
    // libxposed 102 的 AAR 要求 API 37；target 仍为 Android 16（API 36）。
    compileSdk = 37
    buildToolsVersion = "37.0.0"
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "1.1.1"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles("proguard-rules.pro")
            signingConfig = signingConfigs["debug"]
        }
    }

    buildFeatures {
        viewBinding = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    testOptions {
        // JVM 测试中 android.util.Log 等 stub 方法返回默认值而非抛异常（BackendManager 等集成层可测）
        unitTests.isReturnDefaultValues = true
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    compileOnly(libs.libxposed.api)
    implementation(libs.libxposed.service)
    implementation(libs.okhttp)
    testImplementation(libs.junit)
    // 仅测试：JVM 上运行 RuleCatalog（android.jar 的 org.json 是抛异常的 stub）
    testImplementation(libs.orgjson)
}

fun elfLoadAlignments(bytes: ByteArray): List<Long> {
    check(bytes.size >= 64 && bytes[0] == 0x7f.toByte()
        && bytes[1] == 'E'.code.toByte() && bytes[2] == 'L'.code.toByte()
        && bytes[3] == 'F'.code.toByte()) { "Not an ELF shared object" }
    val elfClass = bytes[4].toInt() and 0xff
    val byteOrder = when (bytes[5].toInt() and 0xff) {
        1 -> ByteOrder.LITTLE_ENDIAN
        2 -> ByteOrder.BIG_ENDIAN
        else -> error("Unsupported ELF byte order")
    }
    val buffer = ByteBuffer.wrap(bytes).order(byteOrder)
    fun u16(offset: Int): Int = buffer.getShort(offset).toInt() and 0xffff
    fun u32(offset: Int): Long = buffer.getInt(offset).toLong() and 0xffff_ffffL
    val programOffset: Long
    val entrySize: Int
    val entryCount: Int
    val alignOffset: Int
    when (elfClass) {
        1 -> {
            programOffset = u32(28)
            entrySize = u16(42)
            entryCount = u16(44)
            alignOffset = 28
        }
        2 -> {
            programOffset = buffer.getLong(32)
            entrySize = u16(54)
            entryCount = u16(56)
            alignOffset = 48
        }
        else -> error("Unsupported ELF class: $elfClass")
    }
    check(programOffset >= 0 && entrySize > alignOffset && entryCount > 0) {
        "Invalid ELF program header table"
    }
    return buildList {
        repeat(entryCount) { index ->
            val offsetLong = programOffset + index.toLong() * entrySize
            check(offsetLong in 0..Int.MAX_VALUE.toLong()) { "ELF program header offset overflow" }
            val offset = offsetLong.toInt()
            check(offset + entrySize <= bytes.size) { "Truncated ELF program header table" }
            if (buffer.getInt(offset) == 1) { // PT_LOAD
                add(if (elfClass == 1) u32(offset + alignOffset) else buffer.getLong(offset + alignOffset))
            }
        }
    }
}

fun androidSdkDirectory(projectDir: File): File {
    sequenceOf(System.getenv("ANDROID_SDK_ROOT"), System.getenv("ANDROID_HOME"))
        .filterNotNull().map(::File).firstOrNull(File::isDirectory)?.let { return it }
    val propertiesFile = File(projectDir, "local.properties")
    if (propertiesFile.isFile) {
        val properties = Properties().apply {
            propertiesFile.inputStream().use(::load)
        }
        properties.getProperty("sdk.dir")?.let(::File)?.takeIf(File::isDirectory)?.let { return it }
    }
    error("Android SDK directory is unavailable (set ANDROID_SDK_ROOT or sdk.dir)")
}

tasks.register("verifyXposedReleaseApk") {
    group = "verification"
    description = "Verifies LSPosed metadata, JNI ABI coverage, 16 KiB ELF and APK alignment."
    dependsOn("assembleRelease")
    doLast {
        val apk = layout.buildDirectory.file("outputs/apk/release/app-release.apk").get().asFile
        check(apk.isFile) { "Release APK not found: $apk" }
        val expected = mapOf(
            "META-INF/xposed/java_init.list" to "org.xiyu.githubdirect.ModuleMain\n",
            "META-INF/xposed/module.prop" to "minApiVersion=101\ntargetApiVersion=102\nstaticScope=false\n",
            "META-INF/xposed/scope.list" to "com.github.android\n",
        )
        ZipFile(apk).use { zip ->
            expected.forEach { (path, content) ->
                val entry = checkNotNull(zip.getEntry(path)) { "Missing Xposed metadata: $path" }
                val actual = zip.getInputStream(entry).bufferedReader(Charsets.UTF_8).use { it.readText() }
                check('\r' !in actual) { "$path must use LF line endings" }
                check(actual == content) { "Unexpected content in $path: $actual" }
            }

            val expectedNative = setOf(
                "lib/arm64-v8a/libghdnet.so",
                "lib/armeabi-v7a/libghdnet.so",
                "lib/x86_64/libghdnet.so",
            )
            val actualNative = zip.entries().asSequence()
                .map { it.name }
                .filter { it.endsWith("/libghdnet.so") }
                .toSet()
            check(actualNative == expectedNative) {
                "Unexpected JNI ABI set: $actualNative (expected $expectedNative)"
            }
            expectedNative.forEach { path ->
                val entry = checkNotNull(zip.getEntry(path)) { "Missing JNI library: $path" }
                check(entry.method == ZipEntry.STORED) { "$path must be stored uncompressed for mmap" }
                val alignments = zip.getInputStream(entry).use { it.readBytes() }.let(::elfLoadAlignments)
                check(alignments.isNotEmpty()) { "$path has no PT_LOAD segment" }
                check(alignments.all { it >= 0x4000L }) {
                    "$path has ELF LOAD alignment below 16 KiB: ${alignments.joinToString { "0x${it.toString(16)}" }}"
                }
            }

            val expectedSniGateAssets = setOf(
                "assets/sni-gate/arm64-v8a/sni-gate",
                "assets/sni-gate/armeabi-v7a/sni-gate",
                "assets/sni-gate/x86_64/sni-gate",
            )
            val actualSniGateAssets = zip.entries().asSequence()
                .map { it.name }
                .filter { it.startsWith("assets/sni-gate/") && it.endsWith("/sni-gate") }
                .toSet()
            check(actualSniGateAssets == expectedSniGateAssets) {
                "Unexpected sni-gate ABI set: $actualSniGateAssets"
            }
            val runtimeSource = file(
                "src/main/java/org/xiyu/githubdirect/root/SniGateRuntime.kt",
            ).readText()
            val expectedHashBlock = runtimeSource
                .substringAfter("val EXPECTED_SHA256: Map<String, String> = mapOf(")
                .substringBefore("private const val MAX_BINARY_BYTES")
            val expectedSniGateHashes = Regex(
                "\\\"([^\\\"]+)\\\"\\s+to\\s+\\\"([0-9a-f]{64})\\\"",
            ).findAll(expectedHashBlock).associate { match ->
                match.groupValues[1] to match.groupValues[2]
            }
            check(expectedSniGateHashes.keys == setOf("arm64-v8a", "armeabi-v7a", "x86_64")) {
                "Unexpected SniGateRuntime hash ABI set: ${expectedSniGateHashes.keys}"
            }
            expectedSniGateHashes.forEach { (abi, expectedHash) ->
                val entry = checkNotNull(zip.getEntry("assets/sni-gate/$abi/sni-gate"))
                val digest = MessageDigest.getInstance("SHA-256")
                zip.getInputStream(entry).use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                    }
                }
                val actualHash = digest.digest().joinToString("") { byte ->
                    "%02x".format(byte.toInt() and 0xff)
                }
                check(actualHash == expectedHash) {
                    "sni-gate $abi SHA-256 mismatch: $actualHash (expected $expectedHash)"
                }
            }
            val privateKeyEntries = zip.entries().asSequence()
                .map { it.name }
                .filter { path ->
                    val name = path.substringAfterLast('/').lowercase()
                    name == "ca.key" || name.endsWith(".p12") || name.endsWith(".pfx") ||
                        (name.endsWith(".key") && "public" !in name)
                }
                .toList()
            check(privateKeyEntries.isEmpty()) {
                "Release APK must not package private key material: $privateKeyEntries"
            }

        }

        val sdk = androidSdkDirectory(rootProject.projectDir)
        val buildTools = android.buildToolsVersion
        val zipalign = listOf(
            File(sdk, "build-tools/$buildTools/zipalign"),
            File(sdk, "build-tools/$buildTools/zipalign.exe"),
        ).firstOrNull(File::isFile)
        checkNotNull(zipalign) { "zipalign not found for Build Tools $buildTools under $sdk" }
        val process = ProcessBuilder(
            zipalign.absolutePath,
            "-c", "-P", "16", "-v", "4", apk.absolutePath,
        ).redirectErrorStream(true).start()
        val finished = process.waitFor(30, TimeUnit.SECONDS)
        if (!finished) process.destroyForcibly()
        val zipalignOutput = process.inputStream.bufferedReader().use { it.readText() }
        check(finished && process.exitValue() == 0) {
            "zipalign -P 16 verification failed:\n$zipalignOutput"
        }

        val mapping = layout.buildDirectory.file("outputs/mapping/release/mapping.txt").get().asFile
        check(mapping.isFile) { "R8 mapping not found: $mapping" }
        val stableRuntimeClasses = setOf(
            "org.xiyu.githubdirect.ModuleMain",
            "org.xiyu.githubdirect.root.OriginalDestination",
            "org.xiyu.githubdirect.root.AndroidKeyChainRootHelper",
            "org.xiyu.githubdirect.root.BrowserPolicyRootHelper",
            "org.xiyu.githubdirect.root.OplusHansRootLease",
        )
        val classMappings = mapping.useLines { lines ->
            lines.filter { line -> stableRuntimeClasses.any { line.startsWith("$it -> ") } }.toList()
        }
        stableRuntimeClasses.forEach { className ->
            val classMapping = classMappings.firstOrNull { it.startsWith("$className -> ") }
            check(classMapping == "$className -> $className:") {
                "Runtime entry class was removed or renamed by R8: $classMapping"
            }
        }
    }
}
