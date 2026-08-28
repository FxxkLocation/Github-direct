package org.xiyu.githubdirect.root;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;
import android.system.Os;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Short-lived UID 0 entry point that owns one Android application-restrictions entity.
 *
 * <p>Microsoft Edge 138+ accepts a base64 DER CA through the {@code CACertificates} Android
 * policy. Newer platform revisions support an independently-owned system restrictions entity;
 * Android 16 API 36 instead exposes the legacy UserManager bundle, which is merged conservatively.
 * The helper reads only the public CA while UID 0 and irreversibly drops to UID 1000 before any
 * policy write.</p>
 */
public final class BrowserPolicyRootHelper {
    private static final String MARKER = "GHD_BROWSER_POLICY_V1";
    private static final String DEVICE_POLICY_SERVICE = "device_policy";
    private static final String DEVICE_POLICY_STUB =
            "android.app.admin.IDevicePolicyManager$Stub";
    private static final String USER_SERVICE = "user";
    private static final String USER_MANAGER_STUB = "android.os.IUserManager$Stub";
    private static final String SYSTEM_ENTITY = "org.xiyu.githubdirect.ca_policy";
    private static final String EDGE_PACKAGE = "com.microsoft.emmx";
    private static final String POLICY_CA_CERTIFICATES = "CACertificates";
    private static final String POLICY_PLATFORM_CA = "CAPlatformIntegrationEnabled";
    private static final int SYSTEM_UID = 1000;
    private static final int USER_SYSTEM = 0;
    private static final int MAX_CERT_BYTES = 256 * 1024;

    private BrowserPolicyRootHelper() {}

    public static void main(String[] args) {
        int exit = 1;
        String packageName = "";
        try {
            if (args.length != 3 || Process.myUid() != 0) {
                throw new IllegalArgumentException("root and three arguments required");
            }
            String operation = args[0];
            packageName = args[1];
            if (!"status".equals(operation)
                    && !"install".equals(operation)
                    && !"remove".equals(operation)) {
                throw new IllegalArgumentException("unsupported operation");
            }
            if (!EDGE_PACKAGE.equals(packageName)) {
                throw new IllegalArgumentException("unsupported browser package");
            }

            byte[] expectedDer = loadAndValidatePublicCa(args[2]).getEncoded();
            String expectedBase64 = Base64.getEncoder().encodeToString(expectedDer);
            PolicyBackend backend = policyBackend();
            dropToSystemUid();

            if ("install".equals(operation)) {
                Bundle current = getRestrictions(backend, packageName);
                if (current.containsKey(POLICY_PLATFORM_CA)
                        && !current.getBoolean(POLICY_PLATFORM_CA, false)) {
                    throw new SecurityException("existing policy disables platform CA integration");
                }
                Bundle policies = new Bundle(current);
                policies.putStringArray(
                        POLICY_CA_CERTIFICATES,
                        appendCertificate(current, expectedBase64));
                policies.putBoolean(POLICY_PLATFORM_CA, true);
                setRestrictions(backend, packageName, policies);
            } else if ("remove".equals(operation)) {
                Bundle policies = new Bundle(getRestrictions(backend, packageName));
                if (containsCertificate(policies, expectedBase64)) {
                    String[] remaining = removeCertificate(policies, expectedBase64);
                    if (remaining.length == 0) {
                        policies.remove(POLICY_CA_CERTIFICATES);
                        policies.remove(POLICY_PLATFORM_CA);
                    } else {
                        policies.putStringArray(POLICY_CA_CERTIFICATES, remaining);
                    }
                    setRestrictions(backend, packageName, policies);
                }
            }

            Bundle current = getRestrictions(backend, packageName);
            boolean present = containsCertificate(current, expectedBase64)
                    && current.getBoolean(POLICY_PLATFORM_CA, false);
            boolean ok = "status".equals(operation)
                    || ("install".equals(operation) && present)
                    || ("remove".equals(operation) && !containsCertificate(
                            current, expectedBase64));
            print(ok, present, packageName,
                    (present ? "installed:" : "missing:") + backend.kind);
            exit = ok ? 0 : 1;
        } catch (Throwable t) {
            print(false, false, packageName, safeDetail(unwrap(t)));
        } finally {
            System.out.flush();
            System.err.flush();
            System.exit(exit);
        }
    }

    private static X509Certificate loadAndValidatePublicCa(String path) throws Exception {
        if (path == null || !path.matches(
                "^/data/(user|user_de)/[0-9]+/org\\.xiyu\\.githubdirect/"
                        + "[A-Za-z0-9_./+=~-]+\\.(crt|cer|pem)$")) {
            throw new IllegalArgumentException("unsafe certificate path");
        }
        File file = new File(path).getCanonicalFile();
        if (!file.getPath().matches(
                "^/data/((user|user_de)/[0-9]+|data)/org\\.xiyu\\.githubdirect/"
                        + "[A-Za-z0-9_./+=~-]+\\.(crt|cer|pem)$")) {
            throw new IllegalArgumentException("certificate escapes app storage");
        }
        if (!file.isFile() || file.length() <= 0 || file.length() > MAX_CERT_BYTES) {
            throw new IllegalArgumentException("certificate missing or oversized");
        }
        byte[] input = new byte[(int) file.length()];
        try (FileInputStream stream = new FileInputStream(file)) {
            int offset = 0;
            while (offset < input.length) {
                int count = stream.read(input, offset, input.length - offset);
                if (count < 0) throw new IllegalArgumentException("truncated certificate");
                offset += count;
            }
        }
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(input));
        if (certificate.getBasicConstraints() < 0
                || !certificate.getSubjectX500Principal().equals(
                        certificate.getIssuerX500Principal())) {
            throw new IllegalArgumentException("invalid CA certificate");
        }
        certificate.verify(certificate.getPublicKey());
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            throw new IllegalArgumentException("CA lacks keyCertSign");
        }
        return certificate;
    }

    private static PolicyBackend policyBackend() throws Exception {
        Object devicePolicy = binderInterface(DEVICE_POLICY_SERVICE, DEVICE_POLICY_STUB);
        try {
            devicePolicy.getClass().getMethod(
                    "setApplicationRestrictionsBySystem",
                    String.class,
                    String.class,
                    int.class,
                    Bundle.class);
            devicePolicy.getClass().getMethod(
                    "getApplicationRestrictionsBySystem",
                    String.class,
                    String.class,
                    int.class);
            return new PolicyBackend(devicePolicy, true, "entity");
        } catch (NoSuchMethodException ignored) {
            return new PolicyBackend(
                    binderInterface(USER_SERVICE, USER_MANAGER_STUB),
                    false,
                    "merged");
        }
    }

    private static Object binderInterface(String serviceName, String stubName) throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod("getService", String.class);
        IBinder binder = (IBinder) getService.invoke(null, serviceName);
        if (binder == null) throw new IllegalStateException(serviceName + " unavailable");
        Class<?> stub = Class.forName(stubName);
        Method asInterface = stub.getDeclaredMethod("asInterface", IBinder.class);
        Object service = asInterface.invoke(null, binder);
        if (service == null) throw new IllegalStateException(serviceName + " proxy unavailable");
        return service;
    }

    private static Bundle getRestrictions(PolicyBackend backend, String packageName)
            throws Exception {
        Object result;
        if (backend.entityOwned) {
            result = invoke(
                    backend.service,
                    "getApplicationRestrictionsBySystem",
                    new Class<?>[] {String.class, String.class, int.class},
                    SYSTEM_ENTITY,
                    packageName,
                    USER_SYSTEM);
        } else {
            result = invoke(
                    backend.service,
                    "getApplicationRestrictionsForUser",
                    new Class<?>[] {String.class, int.class},
                    packageName,
                    USER_SYSTEM);
        }
        return result instanceof Bundle ? (Bundle) result : Bundle.EMPTY;
    }

    private static void setRestrictions(PolicyBackend backend, String packageName, Bundle policies)
            throws Exception {
        if (backend.entityOwned) {
            invoke(
                    backend.service,
                    "setApplicationRestrictionsBySystem",
                    new Class<?>[] {String.class, String.class, int.class, Bundle.class},
                    SYSTEM_ENTITY,
                    packageName,
                    USER_SYSTEM,
                    policies);
        } else {
            invoke(
                    backend.service,
                    "setApplicationRestrictions",
                    new Class<?>[] {String.class, Bundle.class, int.class},
                    packageName,
                    policies,
                    USER_SYSTEM);
        }
    }

    private static boolean containsCertificate(Bundle bundle, String expectedBase64) {
        String[] values = bundle.getStringArray(POLICY_CA_CERTIFICATES);
        if (values == null) return false;
        for (String value : values) {
            if (constantTimeEquals(value, expectedBase64)) return true;
        }
        return false;
    }

    private static String[] appendCertificate(Bundle bundle, String expectedBase64) {
        Object raw = bundle.get(POLICY_CA_CERTIFICATES);
        if (raw != null && !(raw instanceof String[])) {
            throw new IllegalArgumentException("existing CACertificates has incompatible type");
        }
        String[] values = raw instanceof String[] ? (String[]) raw : new String[0];
        for (String value : values) {
            if (constantTimeEquals(value, expectedBase64)) return values.clone();
        }
        String[] result = new String[values.length + 1];
        System.arraycopy(values, 0, result, 0, values.length);
        result[values.length] = expectedBase64;
        return result;
    }

    private static String[] removeCertificate(Bundle bundle, String expectedBase64) {
        Object raw = bundle.get(POLICY_CA_CERTIFICATES);
        if (raw == null) return new String[0];
        if (!(raw instanceof String[])) {
            throw new IllegalArgumentException("existing CACertificates has incompatible type");
        }
        String[] values = (String[]) raw;
        int keep = 0;
        for (String value : values) {
            if (!constantTimeEquals(value, expectedBase64)) keep++;
        }
        String[] result = new String[keep];
        int index = 0;
        for (String value : values) {
            if (!constantTimeEquals(value, expectedBase64)) result[index++] = value;
        }
        return result;
    }

    private static boolean constantTimeEquals(String left, String right) {
        byte[] expected = right == null
                ? new byte[0]
                : right.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] actual = left == null
                ? new byte[0]
                : left.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, actual);
    }

    private static void dropToSystemUid() throws Exception {
        Os.setgid(SYSTEM_UID);
        Os.setuid(SYSTEM_UID);
        if (Process.myUid() != SYSTEM_UID) {
            throw new SecurityException("failed to drop privileges");
        }
    }

    private static Object invoke(Object receiver, String name, Class<?>[] parameterTypes,
            Object... args) throws Exception {
        Method method = receiver.getClass().getMethod(name, parameterTypes);
        try {
            return method.invoke(receiver, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw e;
        }
    }

    private static void print(boolean ok, boolean present, String packageName, String detail) {
        System.out.println(MARKER);
        System.out.println("ok=" + (ok ? "1" : "0"));
        System.out.println("present=" + (present ? "1" : "0"));
        System.out.println("package=" + packageName);
        System.out.println("detail=" + detail);
    }

    private static Throwable unwrap(Throwable value) {
        Throwable current = value;
        for (int i = 0; i < 8; i++) {
            if (current instanceof InvocationTargetException
                    && ((InvocationTargetException) current).getCause() != null) {
                current = ((InvocationTargetException) current).getCause();
            } else if (current.getCause() != null
                    && current.getClass().getName().startsWith("java.lang.reflect.")) {
                current = current.getCause();
            } else {
                break;
            }
        }
        return current;
    }

    private static String safeDetail(Throwable t) {
        String name = t == null ? "Unknown" : t.getClass().getSimpleName();
        String message = t == null || t.getMessage() == null ? "" : t.getMessage();
        String value = (name + ":" + message)
                .replace('\n', ' ')
                .replace('\r', ' ')
                .replace('=', ':');
        return value.length() <= 240 ? value : value.substring(0, 240);
    }

    private static final class PolicyBackend {
        final Object service;
        final boolean entityOwned;
        final String kind;

        PolicyBackend(Object service, boolean entityOwned, String kind) {
            this.service = service;
            this.entityOwned = entityOwned;
            this.kind = kind;
        }
    }
}
