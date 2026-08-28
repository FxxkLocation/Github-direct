package org.xiyu.githubdirect.vpn;

import android.util.Log;

import org.xiyu.githubdirect.core.net.ClientHelloAccumulator;
import org.xiyu.githubdirect.core.net.TlsClientHelloRecords;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TCP 透明代理 + TLS ClientHello 分片。
 * <p>
 * 工作在 TUN 层：
 * - 读取 TUN 中的 TCP 包，管理 TCP 状态机
 * - 对目标 IP 的 443 端口建立 protected Socket
 * - 将首个 ClientHello 分片发送（分片逻辑为 core/net/TlsClientHelloRecords 纯函数）
 * - 双向中继数据
 *
 * M1 接口化改造：
 * - RouteTarget(realIp, fragmentTls, idleTimeoutSec) 参数对象
 * - SessionLeaseHook 会话租约（vIP refs 生命周期）
 * - maxSessions 会话上限（超限新 SYN 回 RST）
 * - 分片判定/切分移入 core/net/TlsClientHelloRecords
 */
public class TcpRelay {

    private static final String TAG = "GithubDirect";
    private static final int TCP_CONNECT_TIMEOUT = 10000;
    private static final int TCP_MSS = 1460; // 有效负载上限 = MTU(1500) - IP(20) - TCP(20)
    private static final int TCP_READ_TIMEOUT_MS = 60000;
    private static final int FIN_WAIT_MS = 5000;

    // TCP 状态
    private static final int SYN_RECEIVED = 1;
    private static final int ESTABLISHED = 2;
    private static final int FIN_WAIT = 3;
    private static final int CLOSED = 4;

    private final ConcurrentHashMap<String, TcpSession> sessions = new ConcurrentHashMap<>();
    private final SocketProtector protector;
    private final PacketWriter tunWriter;
    private final SessionLeaseHook leaseHook;
    private final int maxSessions;
    private final Random random = new Random();
    private volatile boolean running = true;

    /** 连接目标参数对象（由调用方按规则策略构造）。 */
    public static class RouteTarget {
        /** 目标真实 IP（4 字节 IPv4）。 */
        public final byte[] realIp;
        /** 是否对首个 ClientHello 做 TLS record 分片。 */
        public final boolean fragmentTls;
        /** 会话空闲超时（秒），0 = 不启用。 */
        public final int idleTimeoutSec;

        public RouteTarget(byte[] realIp, boolean fragmentTls, int idleTimeoutSec) {
            this.realIp = realIp;
            this.fragmentTls = fragmentTls;
            this.idleTimeoutSec = idleTimeoutSec;
        }
    }

    /** 会话租约钩子：SYN 创建会话 → onSessionOpen(vip)；会话关闭 → onSessionClose(vip)。 */
    public interface SessionLeaseHook {
        void onSessionOpen(int vip);

        void onSessionClose(int vip);
    }

    public interface SocketProtector {
        boolean protect(Socket socket);
    }

    public interface PacketWriter {
        void writePacket(byte[] packet);
    }

    public TcpRelay(SocketProtector protector, PacketWriter tunWriter) {
        this(protector, tunWriter, new SessionLeaseHook() {
            @Override
            public void onSessionOpen(int vip) {
            }

            @Override
            public void onSessionClose(int vip) {
            }
        }, 128);
    }

    public TcpRelay(SocketProtector protector, PacketWriter tunWriter,
                    SessionLeaseHook leaseHook, int maxSessions) {
        this.protector = protector;
        this.tunWriter = tunWriter;
        this.leaseHook = leaseHook;
        this.maxSessions = maxSessions > 0 ? maxSessions : 128;
    }

    public void stop() {
        running = false;
        for (TcpSession session : sessions.values()) {
            closeSession(session);
        }
        sessions.clear();
    }

    /**
     * 处理从 TUN 读取的 TCP 数据包。
     *
     * @param packet    完整 IP 包
     * @param ipHdrLen  IP 头长度
     * @param target    连接目标（真实 IP / 分片开关 / 空闲超时）
     */
    public void handlePacket(byte[] packet, int ipHdrLen, RouteTarget target) {
        if (!running) return;

        int totalLen = packet.length;
        if (totalLen < ipHdrLen + 20) return; // 最少 20 字节 TCP 头

        // 解析 TCP 头
        int srcPort = readU16(packet, ipHdrLen);
        int dstPort = readU16(packet, ipHdrLen + 2);
        long seq = readU32(packet, ipHdrLen + 4);
        long ack = readU32(packet, ipHdrLen + 8);
        int flagsWord = readU16(packet, ipHdrLen + 12);
        int tcpHdrLen = ((flagsWord >> 12) & 0xF) * 4;
        boolean syn = (flagsWord & 0x002) != 0;
        boolean ackF = (flagsWord & 0x010) != 0;
        boolean psh = (flagsWord & 0x008) != 0;
        boolean fin = (flagsWord & 0x001) != 0;
        boolean rst = (flagsWord & 0x004) != 0;

        int dataOffset = ipHdrLen + tcpHdrLen;
        int dataLen = totalLen - dataOffset;

        // 保存原始包的 IP 地址（用于构造响应）
        byte[] clientIp = Arrays.copyOfRange(packet, 12, 16);
        byte[] virtualIp = Arrays.copyOfRange(packet, 16, 20);

        // 会话 key 含 IP 四元组：不同客户端源 IP / 不同 vIP 同端口对不会碰撞（§48/§49）
        String key = sessionKey(clientIp, srcPort, virtualIp, dstPort);

        // RST → 清理会话
        if (rst) {
            TcpSession session = sessions.remove(key);
            if (session != null) closeSession(session);
            return;
        }

        // SYN（新连接或重传）
        if (syn && !ackF) {
            TcpSession existing = sessions.get(key);
            if (existing != null && existing.state == SYN_RECEIVED) {
                // SYN 重传 → 重发 SYN-ACK（不更换 seq）
                existing.mySeq.set(existing.mySeq.get() - 1); // sendTcp 会 +1
                sendTcp(existing, true, true, false, false, null);
                Log.d(TAG, "TCP SYN retransmit: " + key);
                return;
            }

            // 清理已有的过期会话
            if (existing != null) {
                sessions.remove(key);
                closeSession(existing);
            }

            // 会话上限：超限新 SYN 直接回 RST（防 fd/线程失控）
            if (sessions.size() >= maxSessions) {
                Log.w(TAG, "maxSessions(" + maxSessions + ") 超限，RST: " + key);
                byte[] rstPacket = buildRst(packet, ipHdrLen);
                if (rstPacket != null) {
                    try {
                        tunWriter.writePacket(rstPacket);
                    } catch (Exception e) {
                        Log.w(TAG, "TUN write RST: " + e.getMessage());
                    }
                }
                return;
            }

            TcpSession session = new TcpSession();
            session.key = key;
            session.clientIp = clientIp;
            session.virtualIp = virtualIp;
            session.realIp = target.realIp;
            session.fragmentTls = target.fragmentTls;
            session.idleTimeoutMs = target.idleTimeoutSec > 0 ? target.idleTimeoutSec * 1000L : 0;
            session.clientPort = srcPort;
            session.serverPort = dstPort;
            session.clientSeqNext = seq + 1;
            session.mySeq = new AtomicLong(1000000L + (long) (Math.random() * 100000));
            session.state = SYN_RECEIVED;
            sessions.put(key, session);

            leaseHook.onSessionOpen(vipToInt(virtualIp));

            // 回复 SYN-ACK
            sendTcp(session, true, true, false, false, null);
            Log.d(TAG, "TCP SYN: " + key + " → " + ipToString(session.realIp) + ":" + dstPort);
            return;
        }

        TcpSession session = sessions.get(key);
        if (session == null) return;

        // 第三次握手 ACK
        if (ackF && session.state == SYN_RECEIVED && dataLen == 0) {
            session.state = ESTABLISHED;
            // 异步连接真实服务器
            new Thread(() -> connectToServer(session), "TCP-" + key).start();
            return;
        }

        // 纯 ACK（来自客户端对我们发送数据的确认，或 FIN_WAIT 中确认我们的 FIN）
        if (ackF && !syn && !fin && dataLen == 0
                && (session.state == ESTABLISHED || session.state == FIN_WAIT)) {
            Log.d(TAG, "Client ACK: " + key + " ack=" + ack);
            return;
        }

        // 数据包
        if (dataLen > 0 && session.state == ESTABLISHED) {
            byte[] data = Arrays.copyOfRange(packet, dataOffset, totalLen);
            session.clientSeqNext = seq + dataLen;
            session.lastActivity = System.currentTimeMillis();

            // 回复 ACK
            sendTcp(session, false, true, false, false, null);

            // 放入写队列（非阻塞）；队列满 → 背压关闭会话
            if (!forwardToServer(session, data)) {
                Log.w(TAG, "Backpressure, session closed: " + key);
            }
            return;
        }

        // 带数据的 SYN_RECEIVED（ACK+Data 合包）
        if (dataLen > 0 && session.state == SYN_RECEIVED && ackF) {
            session.state = ESTABLISHED;
            byte[] data = Arrays.copyOfRange(packet, dataOffset, totalLen);
            session.clientSeqNext = seq + dataLen;
            session.lastActivity = System.currentTimeMillis();
            sendTcp(session, false, true, false, false, null);
            if (!forwardToServer(session, data)) {
                Log.w(TAG, "Backpressure, session closed: " + key);
                return; // 会话已关闭，不再连接服务器
            }
            new Thread(() -> connectToServer(session), "TCP-" + key).start();
            return;
        }

        // 未匹配的数据包
        if (dataLen > 0) {
            Log.w(TAG, "Unhandled data: " + key + " state=" + session.state
                    + " syn=" + syn + " ack=" + ackF + " len=" + dataLen);
        }

        // FIN
        if (fin) {
            session.clientSeqNext = seq + 1;
            sendTcp(session, false, true, true, false, null);
            session.state = CLOSED;
            sessions.remove(key);
            closeSession(session);
        }
    }

    // ==================== 服务器连接 ====================

    private void connectToServer(TcpSession session) {
        try {
            // 使用 SocketChannel 确保 fd 立即可用（protect 需要有效 fd）
            SocketChannel channel = SocketChannel.open();
            Socket socket = channel.socket();
            if (!protector.protect(socket)) {
                Log.e(TAG, "protect() failed for " + session.key);
                channel.close();
                sendRst(session);
                return;
            }

            channel.configureBlocking(true);
            socket.connect(new InetSocketAddress(
                    InetAddress.getByAddress(session.realIp), session.serverPort),
                    TCP_CONNECT_TIMEOUT);
            socket.setTcpNoDelay(true);
            // 读超时与空闲策略对齐：idleTimeout 0 = 不启用 → 无限；否则取 max(60s, idleTimeout)
            //（WebSocket 长连接域 idleTimeout 86400 不得被 60s 读超时误杀）
            int soTimeout = session.idleTimeoutMs <= 0
                    ? 0
                    : (int) Math.max(TCP_READ_TIMEOUT_MS, session.idleTimeoutMs);
            socket.setSoTimeout(soTimeout);

            session.serverSocket = socket;
            session.serverChannel = channel;

            Log.i(TAG, "TCP connected: " + session.key + " → " + ipToString(session.realIp));

            // 启动写线程：从 writeQueue 取出数据，通过 channel.write(ByteBuffer) 写入
            Thread writerThread = new Thread(() -> writerLoop(session), "TCPw-" + session.key);
            writerThread.setDaemon(true);
            writerThread.start();

            // 读取服务器响应 — 使用 InputStream.read()（阻塞模式 + setSoTimeout）
            InputStream in = socket.getInputStream();
            byte[] readBuf = new byte[32768];
            int totalBytes = 0;
            Log.d(TAG, "Waiting for server data: " + session.key);
            int len;
            while (running && session.state == ESTABLISHED && (len = in.read(readBuf)) > 0) {
                session.lastActivity = System.currentTimeMillis();

                if (totalBytes == 0) {
                    Log.i(TAG, "First server data: " + session.key + ", " + len + " bytes");
                } else {
                    Log.d(TAG, "More server data: " + session.key + ", " + len
                            + " bytes (total=" + (totalBytes + len) + ")");
                }
                totalBytes += len;

                // 按 MSS 分段写入 TUN，避免超过 MTU
                int offset = 0;
                while (offset < len) {
                    int chunk = Math.min(len - offset, TCP_MSS);
                    byte[] data = Arrays.copyOfRange(readBuf, offset, offset + chunk);
                    boolean isLast = (offset + chunk >= len);
                    sendTcp(session, false, true, isLast, false, data);
                    offset += chunk;
                }
            }
            Log.i(TAG, "Server stream ended: " + session.key + ", total=" + totalBytes + " bytes");
        } catch (Exception e) {
            Log.w(TAG, "TCP relay error: " + session.key + " - "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (session.state == ESTABLISHED) {
                sendTcp(session, false, true, false, true, null); // FIN
                session.state = FIN_WAIT;
                // 等待客户端发 FIN 完成四次挥手（handlePacket 会处理）
                try { Thread.sleep(FIN_WAIT_MS); } catch (InterruptedException ignored) {}
            }
            // remove-if-same：四元组 key 可能被新会话复用，仅当仍是本会话时才移除（防误删新会话）
            sessions.remove(session.key, session);
            closeSession(session);
        }
    }

    /**
     * 把客户端数据放入写队列（非阻塞，不会卡 VPN 主线程）。
     *
     * @return false = 队列已满（背压）：会话已进入关闭流程（清队列+关 socket，
     *         connectToServer 的 read 循环/writerLoop 自然退出），调用方应停止
     *         向该会话提交数据并打日志。
     */
    private boolean forwardToServer(TcpSession session, byte[] data) {
        if (session.writeQueue.offer(data)) return true;
        // 背压：服务器消费过慢 → 安全关闭会话，防无界队列 OOM
        Log.w(TAG, "Write queue full, closing session (backpressure): " + session.key);
        closeSession(session);
        return false;
    }

    /**
     * 写线程：从 writeQueue 取数据并通过 SocketChannel 写入。
     * 首个 ClientHello 经 ClientHelloAccumulator 累积到完整 record 后，
     * 由 core/net/TlsClientHelloRecords 做多 TLS record + 多 TCP write 分片。
     */
    private void writerLoop(TcpSession session) {
        final ClientHelloAccumulator chAccum = session.chAccum;
        try {
            SocketChannel ch = session.serverChannel;
            if (ch == null || !ch.isConnected()) {
                Log.w(TAG, "Writer: channel not ready for " + session.key);
                return;
            }
            Log.d(TAG, "Writer started: " + session.key);
            while (running && session.state == ESTABLISHED) {
                // 空闲超时检查（配合 read 循环的双向 lastActivity 判定）
                if (session.idleTimeoutMs > 0
                        && System.currentTimeMillis() - session.lastActivity > session.idleTimeoutMs) {
                    Log.i(TAG, "Idle timeout, closing session: " + session.key);
                    break;
                }

                byte[] data = session.writeQueue.poll(1, java.util.concurrent.TimeUnit.SECONDS);
                if (data == null) continue;

                // 首个 ClientHello：累积器补齐/判定（跨多段到达、超时、非 TLS 均可处理）
                if (session.fragmentTls && !chAccum.isPassthrough()) {
                    byte[] out = chAccum.feed(data, System.currentTimeMillis());
                    if (out == null) continue; // 首 record 未齐，等待下一批

                    if (chAccum.consumeFragmented()) {
                        TlsClientHelloRecords.TcpWritePlan writePlan =
                                TlsClientHelloRecords.tcpWritePlan(out);
                        int[] writeEnds = writePlan.getWriteEnds();
                        int start = 0;
                        for (int index = 0; index < writeEnds.length; index++) {
                            int end = writeEnds[index];
                            if (end <= start || end > out.length) continue;
                            channelWrite(ch, out, start, end - start);
                            start = end;
                            if (index == writePlan.getUrgentAfterWriteIndex() && start < out.length) {
                                try {
                                    session.serverSocket.sendUrgentData('a');
                                } catch (Exception ignored) {
                                    // 不支持 TCP urgent data 时继续使用多层分片。
                                }
                            }
                            if (start < out.length) Thread.sleep(TlsClientHelloRecords.WRITE_INTERVAL_MS);
                        }
                        Log.i(TAG, "TLS record fragmented: " + writeEnds.length
                                + " writes, " + out.length + " bytes");
                    } else {
                        // 非分片（放弃分片/超时/非 TLS/判定失败）→ 一次写入
                        channelWrite(ch, out, 0, out.length);
                        Log.d(TAG, "Forwarded to server: " + session.key + " " + out.length + " bytes");
                    }
                } else {
                    channelWrite(ch, data, 0, data.length);
                    Log.d(TAG, "Forwarded to server: " + session.key + " " + data.length + " bytes");
                }
            }
        } catch (InterruptedException e) {
            // 正常退出
        } catch (Exception e) {
            Log.w(TAG, "Writer error: " + session.key + " " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        }
        Log.d(TAG, "Writer exited: " + session.key);
    }

    /** 通过 SocketChannel 写入全部数据（处理 partial write） */
    private void channelWrite(SocketChannel ch, byte[] data, int offset, int length) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(data, offset, length);
        while (buf.hasRemaining()) {
            int written = ch.write(buf);
            if (written < 0) throw new java.io.IOException("Channel write returned " + written);
        }
    }

    // ==================== TCP 包构造 ====================

    /**
     * 对入站 TCP 包构造 RST/ACK 应答包（IP 层交换源/目的）。
     * 用于：lookupReal(vip)==null 时由调用方回 RST（消除静默丢包挂起）。
     */
    public static byte[] buildRst(byte[] packet, int ipHdrLen) {
        if (packet.length < ipHdrLen + 20) return null;
        int totalLen = readU16(packet, 2);
        if (totalLen < ipHdrLen + 20 || totalLen > packet.length) totalLen = packet.length;
        int flagsWord = readU16(packet, ipHdrLen + 12);
        int tcpHdrLen = ((flagsWord >> 12) & 0xF) * 4;
        if (ipHdrLen + tcpHdrLen > totalLen) return null;
        int dataLen = Math.max(0, totalLen - ipHdrLen - tcpHdrLen);
        boolean syn = (flagsWord & 0x002) != 0;

        long seq = readU32(packet, ipHdrLen + 4);
        long ackNum = seq + (syn ? 1 : dataLen);

        int srcPort = readU16(packet, ipHdrLen);
        int dstPort = readU16(packet, ipHdrLen + 2);

        byte[] pkt = new byte[40]; // 20 IP + 20 TCP
        // IPv4 Header
        pkt[0] = 0x45;
        writeU16(pkt, 2, 40);
        writeU16(pkt, 6, 0x4000); // Don't Fragment
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        System.arraycopy(packet, 16, pkt, 12, 4); // Src = 原目的 IP（vIP）
        System.arraycopy(packet, 12, pkt, 16, 4); // Dst = 原源 IP（client）
        writeU16(pkt, 10, 0);
        writeU16(pkt, 10, ipChecksum(pkt, 0, 20));

        // TCP Header
        int t = 20;
        writeU16(pkt, t, dstPort);   // Src port = 原目的端口
        writeU16(pkt, t + 2, srcPort); // Dst port = 原源端口
        writeU32(pkt, t + 4, 0);     // Seq
        writeU32(pkt, t + 8, ackNum); // Ack = 对方 seq + 载荷长度
        writeU16(pkt, t + 12, (5 << 12) | 0x014); // ACK + RST
        writeU16(pkt, t + 14, 0);    // Window
        writeU16(pkt, t + 16, 0);
        writeU16(pkt, t + 16, tcpChecksum(pkt, 20, 20, pkt, 12, pkt, 16));

        return pkt;
    }

    private void sendTcp(TcpSession s, boolean syn, boolean ack, boolean psh, boolean fin, byte[] data) {
        int dataLen = (data != null) ? data.length : 0;
        int tcpLen = 20 + dataLen; // 标准 TCP 头 20 字节
        if (syn) tcpLen += 4; // MSS option
        int totalLen = 20 + tcpLen;

        byte[] pkt = new byte[totalLen];

        // IPv4 Header
        pkt[0] = 0x45;
        writeU16(pkt, 2, totalLen);
        writeU16(pkt, 6, 0x4000); // Don't Fragment
        pkt[8] = 64; // TTL
        pkt[9] = 6;  // TCP
        System.arraycopy(s.virtualIp, 0, pkt, 12, 4); // Src = virtual IP
        System.arraycopy(s.clientIp, 0, pkt, 16, 4);  // Dst = client
        writeU16(pkt, 10, 0);
        writeU16(pkt, 10, ipChecksum(pkt, 0, 20));

        // TCP Header
        int t = 20; // TCP starts at byte 20
        writeU16(pkt, t, s.serverPort);   // Src port (server)
        writeU16(pkt, t + 2, s.clientPort); // Dst port (client)
        long mySeq = s.mySeq.get();
        writeU32(pkt, t + 4, mySeq);      // Seq
        writeU32(pkt, t + 8, s.clientSeqNext); // Ack

        int flags = 0;
        int headerWords = 5; // 20 bytes
        if (syn) {
            flags |= 0x002;
            headerWords = 6; // 24 bytes (with MSS option)
        }
        if (ack) flags |= 0x010;
        if (psh) flags |= 0x008;
        if (fin) flags |= 0x001;
        writeU16(pkt, t + 12, (headerWords << 12) | flags);
        writeU16(pkt, t + 14, 65535); // Window size

        // MSS option (if SYN)
        if (syn) {
            pkt[t + 20] = 0x02; // MSS kind
            pkt[t + 21] = 0x04; // MSS length
            writeU16(pkt, t + 22, 1460); // MSS value
        }

        // Data
        int dataStart = t + headerWords * 4;
        if (data != null) {
            // 调整 totalLen
            totalLen = 20 + headerWords * 4 + dataLen;
            if (pkt.length < totalLen) {
                pkt = Arrays.copyOf(pkt, totalLen);
                writeU16(pkt, 2, totalLen);
                // 重新计算 IP checksum
                writeU16(pkt, 10, 0);
                writeU16(pkt, 10, ipChecksum(pkt, 0, 20));
            }
            System.arraycopy(data, 0, pkt, dataStart, dataLen);
        } else {
            totalLen = 20 + headerWords * 4;
            if (pkt.length != totalLen) {
                pkt = Arrays.copyOf(pkt, totalLen);
                writeU16(pkt, 2, totalLen);
                writeU16(pkt, 10, 0);
                writeU16(pkt, 10, ipChecksum(pkt, 0, 20));
            }
        }

        // TCP checksum
        int tcpTotalLen = totalLen - 20;
        writeU16(pkt, t + 16, 0);
        writeU16(pkt, t + 16, tcpChecksum(pkt, 20, tcpTotalLen, pkt, 12, pkt, 16));

        // 更新 seq
        long advance = dataLen;
        if (syn) advance++;
        if (fin) advance++;
        s.mySeq.addAndGet(advance);

        try {
            tunWriter.writePacket(Arrays.copyOf(pkt, totalLen));
            if (dataLen > 0) {
                Log.d(TAG, "TUN ← " + s.key + " seq=" + mySeq + " len=" + dataLen
                        + " total=" + totalLen);
            }
        } catch (Exception e) {
            Log.w(TAG, "TUN write error: " + e.getMessage());
        }
    }

    private void sendRst(TcpSession s) {
        int totalLen = 40; // 20 IP + 20 TCP
        byte[] pkt = new byte[totalLen];

        pkt[0] = 0x45;
        writeU16(pkt, 2, totalLen);
        pkt[8] = 64;
        pkt[9] = 6;
        System.arraycopy(s.virtualIp, 0, pkt, 12, 4);
        System.arraycopy(s.clientIp, 0, pkt, 16, 4);
        writeU16(pkt, 10, 0);
        writeU16(pkt, 10, ipChecksum(pkt, 0, 20));

        int t = 20;
        writeU16(pkt, t, s.serverPort);
        writeU16(pkt, t + 2, s.clientPort);
        writeU32(pkt, t + 4, s.mySeq.get());
        writeU32(pkt, t + 8, s.clientSeqNext);
        writeU16(pkt, t + 12, (5 << 12) | 0x014); // ACK + RST
        writeU16(pkt, t + 14, 0);
        writeU16(pkt, t + 16, 0);
        writeU16(pkt, t + 16, tcpChecksum(pkt, 20, 20, pkt, 12, pkt, 16));

        try {
            tunWriter.writePacket(pkt);
        } catch (Exception ignored) {
        }

        sessions.remove(s.key);
        closeSession(s);
    }

    private void closeSession(TcpSession session) {
        // 租约关闭恰好一次
        if (session.leaseClosed.compareAndSet(false, true)) {
            leaseHook.onSessionClose(vipToInt(session.virtualIp));
        }
        // 放入毒丸让写线程退出
        session.writeQueue.clear();
        if (session.serverChannel != null) {
            try {
                session.serverChannel.close();
            } catch (Exception ignored) {
            }
        }
        if (session.serverSocket != null) {
            try {
                session.serverSocket.close();
            } catch (Exception ignored) {
            }
        }
    }

    // ==================== 工具方法 ====================

    private static int vipToInt(byte[] ip) {
        return ((ip[0] & 0xFF) << 24) | ((ip[1] & 0xFF) << 16)
                | ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
    }

    private static int readU16(byte[] d, int o) {
        return ((d[o] & 0xFF) << 8) | (d[o + 1] & 0xFF);
    }

    private static long readU32(byte[] d, int o) {
        return ((long) (d[o] & 0xFF) << 24) | ((long) (d[o + 1] & 0xFF) << 16)
                | ((long) (d[o + 2] & 0xFF) << 8) | (d[o + 3] & 0xFF);
    }

    private static void writeU16(byte[] d, int o, int v) {
        d[o] = (byte) ((v >> 8) & 0xFF);
        d[o + 1] = (byte) (v & 0xFF);
    }

    private static void writeU32(byte[] d, int o, long v) {
        d[o] = (byte) ((v >> 24) & 0xFF);
        d[o + 1] = (byte) ((v >> 16) & 0xFF);
        d[o + 2] = (byte) ((v >> 8) & 0xFF);
        d[o + 3] = (byte) (v & 0xFF);
    }

    private static int ipChecksum(byte[] data, int offset, int length) {
        long sum = 0;
        for (int i = 0; i < length; i += 2) {
            int word;
            if (i + 1 < length)
                word = ((data[offset + i] & 0xFF) << 8) | (data[offset + i + 1] & 0xFF);
            else
                word = (data[offset + i] & 0xFF) << 8;
            sum += word;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    /**
     * TCP 校验和，包含伪头部。
     */
    private static int tcpChecksum(byte[] pkt, int tcpOffset, int tcpLen,
                                   byte[] srcIpPkt, int srcIpOffset,
                                   byte[] dstIpPkt, int dstIpOffset) {
        long sum = 0;
        // 伪头部: src IP
        sum += ((srcIpPkt[srcIpOffset] & 0xFF) << 8) | (srcIpPkt[srcIpOffset + 1] & 0xFF);
        sum += ((srcIpPkt[srcIpOffset + 2] & 0xFF) << 8) | (srcIpPkt[srcIpOffset + 3] & 0xFF);
        // 伪头部: dst IP
        sum += ((dstIpPkt[dstIpOffset] & 0xFF) << 8) | (dstIpPkt[dstIpOffset + 1] & 0xFF);
        sum += ((dstIpPkt[dstIpOffset + 2] & 0xFF) << 8) | (dstIpPkt[dstIpOffset + 3] & 0xFF);
        // 伪头部: protocol (6=TCP) + TCP length
        sum += 6;
        sum += tcpLen;

        // TCP header + data
        for (int i = 0; i < tcpLen; i += 2) {
            int word;
            if (i + 1 < tcpLen)
                word = ((pkt[tcpOffset + i] & 0xFF) << 8) | (pkt[tcpOffset + i + 1] & 0xFF);
            else
                word = (pkt[tcpOffset + i] & 0xFF) << 8;
            sum += word;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    private static String ipToString(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    /**
     * 会话 key：srcIp:srcPort:dstIp(vIP):dstPort。
     * 含 IP 的四元组，避免不同客户端源 IP 或不同 vIP 同端口对时碰撞
     * （原实现仅 srcPort:dstPort，多客户端会串会话）。示例："1.2.3.4:12345:10.0.0.10:443"。
     */
    public static String sessionKey(byte[] srcIp, int srcPort, byte[] dstIp, int dstPort) {
        return ipToString(srcIp) + ":" + srcPort + ":" + ipToString(dstIp) + ":" + dstPort;
    }

    // ==================== Session ====================

    static class TcpSession {
        String key;
        byte[] clientIp;
        byte[] virtualIp;
        byte[] realIp;
        boolean fragmentTls;
        long idleTimeoutMs;
        int clientPort;
        int serverPort;
        long clientSeqNext;
        AtomicLong mySeq;
        /** 多线程读写（VPN 主循环 / connect 线程 / writer 线程）→ volatile 保证可见性。 */
        volatile int state;
        volatile long lastActivity = System.currentTimeMillis();
        final AtomicBoolean leaseClosed = new AtomicBoolean(false);

        Socket serverSocket;
        SocketChannel serverChannel;

        // 写队列：VPN 主线程只向队列提交数据，connectToServer 线程负责写入。
        // 有界 64 段（每段 ≤ 客户端段大小）：服务器消费过慢时 offer 失败 → 背压关闭会话，防无界 OOM
        final LinkedBlockingQueue<byte[]> writeQueue = new LinkedBlockingQueue<>(64);

        /** TLS ClientHello 累积器（仅 fragmentTls 会话使用；writerLoop 单线程访问）。 */
        final ClientHelloAccumulator chAccum = new ClientHelloAccumulator();
    }
}
