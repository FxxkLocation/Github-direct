package org.xiyu.githubdirect.root;

import android.os.Process;
import android.system.Os;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

/**
 * Short-lived {@code app_process} entry point used by {@link AndroidSystemCaInstaller}.
 *
 * <p>The helper starts as UID 0 only long enough to read the module's public CA file. It validates
 * and converts the certificate to DER, irreversibly drops to Android's system UID, then uses the
 * platform Conscrypt {@code TrustedCertificateStore}. That is the same implementation used by
 * KeyChainService, including subject-hash collision and tombstone handling. The CA private key is
 * never read by this class and no trust-all hook is installed.</p>
 */
public final class AndroidKeyChainRootHelper {
    private static final String STORE_CLASS =
            "com.android.org.conscrypt.TrustedCertificateStore";
    private static final File EMPTY_SYSTEM_STORE = new File("/dev/null");
    private static final File USER_ADDED_STORE =
            new File("/data/misc/keychain/cacerts-added");
    private static final File USER_REMOVED_STORE =
            new File("/data/misc/keychain/cacerts-removed");
    private static final int SYSTEM_UID = 1000;
    private static final int MAX_CERT_BYTES = 256 * 1024;

    private AndroidKeyChainRootHelper() {}

    public static void main(String[] args) {
        int exit = 1;
        try {
            if (args.length != 2 || Process.myUid() != 0) {
                throw new IllegalArgumentException(
                        "root and two arguments required (uid=" + Process.myUid()
                                + ",args=" + args.length + ")");
            }
            String operation = args[0];
            if (!"install".equals(operation)
                    && !"status".equals(operation)
                    && !"remove".equals(operation)) {
                throw new IllegalArgumentException("unsupported operation");
            }

            X509Certificate certificate = loadAndValidatePublicCa(args[1]);
            byte[] expectedDer = certificate.getEncoded();
            Class<?> storeClass = Class.forName(STORE_CLASS);
            Object store = storeClass.getConstructor().newInstance();
            // installCertificate() intentionally does nothing when the same certificate is already
            // present in the system/APEX store. Chromium-based clients nevertheless need a user:
            // alias for a locally generated interception CA. Keep Conscrypt's collision/tombstone
            // implementation, but hide only the system roots from the install operation.
            Object userStoreWriter = storeClass
                    .getConstructor(File.class, File.class, File.class)
                    .newInstance(EMPTY_SYSTEM_STORE, USER_ADDED_STORE, USER_REMOVED_STORE);
            dropToSystemUid();
            Result result = execute(operation, certificate, expectedDer, store, userStoreWriter);
            printResult(result);
            exit = result.ok ? 0 : 1;
        } catch (Throwable t) {
            Throwable root = unwrap(t);
            System.out.println("GHD_KEYCHAIN_V1");
            System.out.println("ok=0");
            System.out.println("present=0");
            System.out.println("alias=");
            System.out.println("detail=" + safeDetail(root));
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
        if (certificate.getBasicConstraints() < 0) {
            throw new IllegalArgumentException("certificate is not a CA");
        }
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            throw new IllegalArgumentException("CA is not self-issued");
        }
        certificate.verify(certificate.getPublicKey());
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            throw new IllegalArgumentException("CA lacks keyCertSign");
        }
        return certificate;
    }

    private static void dropToSystemUid() throws Exception {
        Os.setgid(SYSTEM_UID);
        Os.setuid(SYSTEM_UID);
        if (Process.myUid() != SYSTEM_UID) {
            throw new SecurityException("failed to drop privileges");
        }
    }

    private static Result execute(String operation, X509Certificate certificate,
            byte[] expectedDer, Object store, Object userStoreWriter) throws Exception {
        List<String> aliases = matchingAndroidCaStoreAliases(expectedDer);
        if ("install".equals(operation) && aliases.isEmpty()) {
            invoke(
                    userStoreWriter,
                    "installCertificate",
                    new Class<?>[] {X509Certificate.class},
                    certificate);
            aliases = matchingAndroidCaStoreAliases(expectedDer);
        } else if ("remove".equals(operation)) {
            for (String alias : matchingStoreAliases(store, expectedDer)) {
                invoke(
                        store,
                        "deleteCertificateEntry",
                        new Class<?>[] {String.class},
                        alias);
            }
            aliases = matchingAndroidCaStoreAliases(expectedDer);
        }

        boolean present = !aliases.isEmpty();
        boolean ok = "status".equals(operation)
                || ("install".equals(operation) && present)
                || ("remove".equals(operation) && !present);
        String alias = present ? aliases.get(0) : "";
        String detail;
        if ("install".equals(operation)) {
            detail = present ? "installed" : "install verification failed";
        } else if ("remove".equals(operation)) {
            detail = present ? "remove verification failed" : "removed";
        } else {
            detail = present ? "present" : "missing";
        }
        return new Result(ok, present, alias, detail);
    }

    /** Mirrors Chromium X509Util.getUserAddedRoots() through AndroidCAStore. */
    private static List<String> matchingAndroidCaStoreAliases(byte[] expectedDer)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
        keyStore.load(null);
        List<String> matches = new ArrayList<>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!alias.matches("^user:[0-9a-f]{8}\\.[0-9]+$")) continue;
            Certificate certificate = keyStore.getCertificate(alias);
            if (certificate != null
                    && MessageDigest.isEqual(expectedDer, certificate.getEncoded())) {
                matches.add(alias);
            }
        }
        Collections.sort(matches);
        return matches;
    }

    private static List<String> matchingStoreAliases(Object store, byte[] expectedDer)
            throws Exception {
        Object rawAliases = invoke(store, "userAliases", new Class<?>[0]);
        if (!(rawAliases instanceof Set<?>)) return Collections.emptyList();
        List<String> matches = new ArrayList<>();
        for (Object value : (Set<?>) rawAliases) {
            if (!(value instanceof String)) continue;
            String alias = (String) value;
            if (!alias.matches("^user:[0-9a-f]{8}\\.[0-9]+$")) continue;
            Object rawCertificate = invoke(
                    store,
                    "getCertificate",
                    new Class<?>[] {String.class},
                    alias);
            if (rawCertificate instanceof Certificate
                    && MessageDigest.isEqual(
                            expectedDer,
                            ((Certificate) rawCertificate).getEncoded())) {
                matches.add(alias);
            }
        }
        Collections.sort(matches);
        return matches;
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

    private static void printResult(Result result) {
        System.out.println("GHD_KEYCHAIN_V1");
        System.out.println("ok=" + (result.ok ? "1" : "0"));
        System.out.println("present=" + (result.present ? "1" : "0"));
        System.out.println("alias=" + result.alias);
        System.out.println("detail=" + result.detail);
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

    private static final class Result {
        final boolean ok;
        final boolean present;
        final String alias;
        final String detail;

        Result(boolean ok, boolean present, String alias, String detail) {
            this.ok = ok;
            this.present = present;
            this.alias = alias == null ? "" : alias;
            this.detail = detail == null ? "" : detail;
        }
    }
}
