package org.xiyu.githubdirect.root;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

/** UID 0 app_process entry point; launched only by {@link OemFreezeLease}. */
public final class OplusHansRootLease {
    private static final String SERVICE = "oplus_freeze";
    private static final String MANAGER_DESCRIPTOR = "com.oplus.app.IOplusHansFreezeManager";
    private static final String CALLBACK_DESCRIPTOR = "com.oplus.app.IOplusProtectConnection";
    private static final int TRANSACTION_REQUEST_DELAY = 8;
    private static final int TRANSACTION_CANCEL_DELAY = 9;
    private static final int CALLBACK_SUCCESS = 1;
    private static final int CALLBACK_ERROR = 2;
    private static final int CALLBACK_TIMEOUT = 3;
    private static final String REASON = "GithubDirectRootRelay";

    private OplusHansRootLease() {}

    public static void main(String[] args) {
        if (args.length != 6 || Process.myUid() != 0) return;
        final int uid;
        final int appPid;
        try {
            uid = Integer.parseInt(args[0]);
            appPid = Integer.parseInt(args[2]);
        } catch (RuntimeException ignored) {
            return;
        }
        final String packageName = args[1];
        final File pidFile = safeFile(args[3]);
        final File statusFile = safeFile(args[4]);
        final File stopFile = safeFile(args[5]);
        if (uid <= 0 || appPid <= 0 || !"org.xiyu.githubdirect".equals(packageName)
                || pidFile == null || statusFile == null || stopFile == null) return;

        IBinder service = null;
        final AtomicBoolean terminal = new AtomicBoolean(false);
        boolean preserveStatus = false;
        try {
            service = getService();
            if (service == null) throw new IllegalStateException("oplus_freeze unavailable");
            final Callback callback = new Callback(statusFile, terminal, appPid);
            write(pidFile, Integer.toString(Process.myPid()));
            requestDelay(service, uid, packageName, callback);
            if (!terminal.get()) write(statusFile, activeStatus(appPid));

            final IBinder finalService = service;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> cancelQuietly(finalService, uid)));
            while (!terminal.get() && !stopFile.exists() && processMatches(appPid, packageName)) {
                Thread.sleep(2_000L);
            }
            preserveStatus = statusStartsWithError(statusFile);
        } catch (Throwable t) {
            preserveStatus = true;
            writeQuietly(statusFile, "error:" + t.getClass().getSimpleName());
        } finally {
            if (service != null) cancelQuietly(service, uid);
            deleteQuietly(pidFile);
            if (!preserveStatus) deleteQuietly(statusFile);
            deleteQuietly(stopFile);
        }
    }

    private static String activeStatus(int appPid) {
        return "active:" + appPid;
    }

    private static boolean statusStartsWithError(File file) {
        byte[] bytes = new byte[64];
        try (FileInputStream input = new FileInputStream(file)) {
            int count = input.read(bytes);
            return count > 0 && new String(bytes, 0, count, StandardCharsets.US_ASCII)
                    .startsWith("error:");
        } catch (Exception ignored) {
            return false;
        }
    }

    private static IBinder getService() throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod("getService", String.class);
        return (IBinder) getService.invoke(null, SERVICE);
    }

    private static void requestDelay(IBinder service, int uid, String packageName, IBinder callback)
            throws RemoteException {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(MANAGER_DESCRIPTOR);
            data.writeInt(uid);
            data.writeString(packageName);
            data.writeLong(0L); // 厂商 API 约定：0 = 连接 Binder 存活期间持续保护。
            data.writeString(REASON);
            data.writeStrongBinder(callback);
            if (!service.transact(TRANSACTION_REQUEST_DELAY, data, reply, 0)) {
                throw new RemoteException("requestFrozenDelay transact=false");
            }
            reply.readException();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static void cancelQuietly(IBinder service, int uid) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(MANAGER_DESCRIPTOR);
            data.writeInt(uid);
            if (service.transact(TRANSACTION_CANCEL_DELAY, data, reply, 0)) reply.readException();
        } catch (Throwable ignored) {
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static boolean processMatches(int pid, String packageName) {
        File cmdline = new File("/proc/" + pid + "/cmdline");
        if (!cmdline.isFile()) return false;
        byte[] bytes = new byte[256];
        try (FileInputStream input = new FileInputStream(cmdline)) {
            int count = input.read(bytes);
            if (count <= 0) return false;
            int end = 0;
            while (end < count && bytes[end] != 0) end++;
            return packageName.equals(new String(bytes, 0, end, StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            return false;
        }
    }

    private static File safeFile(String path) {
        if (path == null || !path.matches("^/data/local/tmp/ghd_hans_[0-9]+\\.(pid|status|stop)$")) {
            return null;
        }
        return new File(path);
    }

    private static void write(File file, String value) throws Exception {
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(value.getBytes(StandardCharsets.US_ASCII));
            output.flush();
        }
    }

    private static void writeQuietly(File file, String value) {
        try {
            write(file, value);
        } catch (Exception ignored) {
        }
    }

    private static void deleteQuietly(File file) {
        try {
            if (file != null) file.delete();
        } catch (RuntimeException ignored) {
        }
    }

    private static final class Callback extends Binder {
        private final File statusFile;
        private final AtomicBoolean terminal;
        private final int appPid;

        Callback(File statusFile, AtomicBoolean terminal, int appPid) {
            this.statusFile = statusFile;
            this.terminal = terminal;
            this.appPid = appPid;
            attachInterface(null, CALLBACK_DESCRIPTOR);
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code == INTERFACE_TRANSACTION) {
                if (reply != null) reply.writeString(CALLBACK_DESCRIPTOR);
                return true;
            }
            if (code < CALLBACK_SUCCESS || code > CALLBACK_TIMEOUT) {
                return super.onTransact(code, data, reply, flags);
            }
            data.enforceInterface(CALLBACK_DESCRIPTOR);
            if (code == CALLBACK_SUCCESS) {
                writeQuietly(statusFile, activeStatus(appPid));
            } else {
                int error = code == CALLBACK_ERROR ? data.readInt() : 0;
                writeQuietly(statusFile, "error:" + error);
                terminal.set(true);
            }
            return true;
        }
    }
}
