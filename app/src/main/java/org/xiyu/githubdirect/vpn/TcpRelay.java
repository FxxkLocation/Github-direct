package org.xiyu.githubdirect.vpn;

import android.util.Log;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TCP 透明代理 + TLS ClientHello 分片。
 * <p>
 * 工作在 TUN 层：
 * - 读取 TUN 中的 TCP 包，管理 TCP 状态机
 * - 对 GitHub IP 的 443 端口建立 protected Socket
 * - 将首个 ClientHello 分片发送（绕过 GFW SNI 检测）
 * - 双向中继数据
 */
public class TcpRelay {

    private static final String TAG = "GithubDirect";
    private static final int TCP_CONNECT_TIMEOUT = 10000;
    private static final int TCP_MSS = 1460; // 有效负载上限 = MTU(1500) - IP(20) - TCP(20)

    // ClientHello 分片点：在 TLS Record Header (5字节) 后切割
    // GFW 需要读完整个 ClientHello 才能提取 SNI
    private static final int SPLIT_POSITION = 5;
    private static final int SPLIT_DELAY_MS = 200;

    // TCP 状态
    private static final int SYN_RECEIVED = 1;
    private static final int ESTABLISHED = 2;
    private static final int FIN_WAIT = 3;
    private static final int CLOSED = 4;

    private final ConcurrentHashMap<String, TcpSession> sessions = new ConcurrentHashMap<>();
    private final SocketProtector protector;
    private final PacketWriter tunWriter;
    private final Random random = new Random();
    private volatile boolean running = true;

    public interface SocketProtector {
        boolean protect(Socket socket);
    }

    public interface PacketWriter {
        void writePacket(byte[] packet);
    }

    public TcpRelay(SocketProtector protector, PacketWriter tunWriter) {
        this.protector = protector;
        this.tunWriter = tunWriter;
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
     * @param realIp    目标 GitHub 的真实 IP（4 字节）
     */
    public void handlePacket(byte[] packet, int ipHdrLen, byte[] realIp) {
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

        String key = srcPort + ":" + dstPort;

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

            TcpSession session = new TcpSession();
            session.key = key;
            session.clientIp = clientIp;
            session.virtualIp = virtualIp;
            session.realIp = realIp;
            session.clientPort = srcPort;
            session.serverPort = dstPort;
            session.clientSeqNext = seq + 1;
            session.mySeq = new AtomicLong(1000000L + (long) (Math.random() * 100000));
            session.state = SYN_RECEIVED;
            sessions.put(key, session);

            // 回复 SYN-ACK
            sendTcp(session, true, true, false, false, null);
            Log.d(TAG, "TCP SYN: " + key + " → " + ipToString(realIp) + ":" + dstPort);
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

            // 回复 ACK
            sendTcp(session, false, true, false, false, null);

            // 放入写队列（非阻塞，不会卡 VPN 主线程）
            forwardToServer(session, data);
            return;
        }

        // 带数据的 SYN_RECEIVED（ACK+Data 合包）
        if (dataLen > 0 && session.state == SYN_RECEIVED && ackF) {
            session.state = ESTABLISHED;
            byte[] data = Arrays.copyOfRange(packet, dataOffset, totalLen);
            session.clientSeqNext = seq + dataLen;
            sendTcp(session, false, true, false, false, null);
            forwardToServer(session, data);
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
            socket.setSoTimeout(60000); // 读超时 60s

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
                try { Thread.sleep(5000); } catch (InterruptedException ignored) {}
            }
            sessions.remove(session.key);
            closeSession(session);
        }
    }

    private void forwardToServer(TcpSession session, byte[] data) {
        // 非阻塞：只放入写队列，由 connectToServer 的写线程消费
        session.writeQueue.offer(data);
    }

    /**
     * 写线程：从 writeQueue 取数据并通过 SocketChannel 写入。
     * 第一个 ClientHello 做 TLS 记录层分片。
     */
    private void writerLoop(TcpSession session) {
        boolean firstData = true;
        try {
            SocketChannel ch = session.serverChannel;
            if (ch == null || !ch.isConnected()) {
                Log.w(TAG, "Writer: channel not ready for " + session.key);
                return;
            }
            Log.d(TAG, "Writer started: " + session.key);
            while (running && session.state == ESTABLISHED) {
                byte[] data = session.writeQueue.poll(1, java.util.concurrent.TimeUnit.SECONDS);
                if (data == null) continue;

                // 合并队列中紧接着的数据
                byte[] extra;
                while ((extra = session.writeQueue.poll()) != null) {
                    byte[] combined = new byte[data.length + extra.length];
                    System.arraycopy(data, 0, combined, 0, data.length);
                    System.arraycopy(extra, 0, combined, data.length, extra.length);
                    data = combined;
                }

                if (firstData && isTlsClientHello(data)) {
                    firstData = false;
                    byte[] fragmented = fragmentTlsRecord(data);
                    if (fragmented != null) {
                        int firstRecordEnd = 5 + ((fragmented[3] & 0xFF) << 8 | (fragmented[4] & 0xFF));
                        channelWrite(ch, fragmented, 0, firstRecordEnd);
                        Log.d(TAG, "Writer: first fragment sent " + firstRecordEnd + " bytes");
                        Thread.sleep(SPLIT_DELAY_MS);
                        channelWrite(ch, fragmented, firstRecordEnd, fragmented.length - firstRecordEnd);
                        Log.i(TAG, "TLS record fragmented: " + firstRecordEnd + " + "
                                + (fragmented.length - firstRecordEnd) + " bytes (SNI-aware)");
                    } else {
                        channelWrite(ch, data, 0, 1);
                        Thread.sleep(SPLIT_DELAY_MS);
                        channelWrite(ch, data, 1, data.length - 1);
                        Log.i(TAG, "ClientHello fallback split: 1 + " + (data.length - 1) + " bytes");
                    }
                } else {
                    firstData = false;
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

    /**
     * 检查数据是否为 TLS ClientHello。
     * TLS Record: type=0x16 (Handshake), version=0x0301/0x0303, then Handshake type=0x01 (ClientHello)
     */
    private boolean isTlsClientHello(byte[] data) {
        return data.length > 5
                && data[0] == 0x16          // TLS Handshake
                && data[1] == 0x03          // Version major = 3
                && (data[2] >= 0x01 && data[2] <= 0x04) // Version minor 1-4
                && data[5] == 0x01;         // ClientHello
    }

    /**
     * TLS 记录层分片：将一个 TLS 记录拆成两个独立的 TLS 记录。
     * 在 SNI 域名中间分割，使 GFW DPI 无法从单个 TLS 记录中提取完整 SNI。
     *
     * @return 两个相邻的 TLS 记录的字节数组，或 null（无法分片）
     */
    private byte[] fragmentTlsRecord(byte[] data) {
        if (data.length < 10) return null;

        // 原始 TLS Record: [type(1)][version(2)][length(2)] + [handshake_data]
        int recordDataLen = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
        if (5 + recordDataLen > data.length) return null;

        byte tlsType = data[0];
        byte verMaj = data[1];
        byte verMin = data[2];

        // 找到 SNI 在 handshake data 中的偏移量（相对于 record 数据起始 offset=5）
        int sniOffset = findSniOffset(data, 5, recordDataLen);
        int splitPoint;

        if (sniOffset > 0) {
            // 在 SNI 域名中间切割
            splitPoint = sniOffset + 3; // 切到 SNI hostname 的前 3 个字节
            Log.d(TAG, "SNI found at handshake offset " + (sniOffset - 5) + ", split at " + splitPoint);
        } else {
            // 找不到 SNI，在 handshake data 中间切
            splitPoint = 5 + Math.min(recordDataLen / 2, 50);
            Log.d(TAG, "SNI not found, split at middle: " + splitPoint);
        }

        if (splitPoint <= 5 || splitPoint >= 5 + recordDataLen) return null;

        int firstLen = splitPoint - 5;    // 第一个 TLS 记录的数据长度
        int secondLen = recordDataLen - firstLen; // 第二个 TLS 记录的数据长度

        // 构建两个 TLS 记录
        byte[] result = new byte[5 + firstLen + 5 + secondLen];

        // Record 1
        result[0] = tlsType;
        result[1] = verMaj;
        result[2] = verMin;
        result[3] = (byte) ((firstLen >> 8) & 0xFF);
        result[4] = (byte) (firstLen & 0xFF);
        System.arraycopy(data, 5, result, 5, firstLen);

        // Record 2
        int off2 = 5 + firstLen;
        result[off2] = tlsType;
        result[off2 + 1] = verMaj;
        result[off2 + 2] = verMin;
        result[off2 + 3] = (byte) ((secondLen >> 8) & 0xFF);
        result[off2 + 4] = (byte) (secondLen & 0xFF);
        System.arraycopy(data, splitPoint, result, off2 + 5, secondLen);

        return result;
    }

    /**
     * 在 TLS ClientHello 中查找 SNI 域名的起始偏移（在整个 data 数组中的绝对偏移）。
     *
     * ClientHello 结构:
     *   handshake_type(1) + length(3) + version(2) + random(32) + session_id(1+var)
     *   + cipher_suites(2+var) + compression(1+var) + extensions_len(2) + extensions
     *
     * SNI extension:
     *   ext_type(2) = 0x0000 + ext_len(2) + server_name_list_len(2)
     *   + name_type(1) + name_len(2) + name(var)
     *
     * @return SNI 域名字符串的起始绝对偏移，或 -1
     */
    private int findSniOffset(byte[] data, int recordStart, int recordLen) {
        int pos = recordStart;
        int end = recordStart + recordLen;

        // Handshake header: type(1) + length(3)
        if (pos + 4 > end) return -1;
        pos += 4;

        // ClientHello: version(2) + random(32) = 34 bytes
        if (pos + 34 > end) return -1;
        pos += 34;

        // Session ID: length(1) + data
        if (pos + 1 > end) return -1;
        int sidLen = data[pos] & 0xFF;
        pos += 1 + sidLen;

        // Cipher Suites: length(2) + data
        if (pos + 2 > end) return -1;
        int csLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2 + csLen;

        // Compression Methods: length(1) + data
        if (pos + 1 > end) return -1;
        int cmLen = data[pos] & 0xFF;
        pos += 1 + cmLen;

        // Extensions: length(2)
        if (pos + 2 > end) return -1;
        int extTotalLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        int extEnd = pos + extTotalLen;
        if (extEnd > end) extEnd = end;

        // 遍历 extensions 寻找 SNI (type = 0x0000)
        while (pos + 4 <= extEnd) {
            int extType = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            int extLen = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);

            if (extType == 0x0000 && extLen > 5) {
                // SNI extension: list_len(2) + name_type(1) + name_len(2) + name
                int sniDataStart = pos + 4;
                if (sniDataStart + 5 <= extEnd) {
                    // name_type(1 byte at +2) name_len(2 bytes at +3) name(at +5)
                    int nameStart = sniDataStart + 5;
                    if (nameStart < extEnd) {
                        return nameStart; // SNI 域名字符串的起始位置
                    }
                }
            }

            pos += 4 + extLen;
        }

        return -1;
    }

    // ==================== TCP 包构造 ====================

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

    // ==================== Session ====================

    static class TcpSession {
        String key;
        byte[] clientIp;
        byte[] virtualIp;
        byte[] realIp;
        int clientPort;
        int serverPort;
        long clientSeqNext;
        AtomicLong mySeq;
        int state;
        boolean firstData = true;
        byte[] pendingData;

        Socket serverSocket;
        SocketChannel serverChannel;

        // 写队列：VPN 主线程只向队列提交数据，connectToServer 线程负责写入
        final LinkedBlockingQueue<byte[]> writeQueue = new LinkedBlockingQueue<>();
    }
}
