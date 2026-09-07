package handshake.validator;

import java.io.*;
import java.net.Socket;

/**
 * A single, already-upgraded WebSocket connection -- handles RFC 6455
 * frame encoding/decoding for discrete binary messages. Client frames
 * are masked (required by the RFC); server frames are never masked
 * (also required). Doesn't handle message fragmentation (multi-frame
 * messages with FIN=0) -- not needed here, since every message this
 * project sends over this connection (Brontide handshake acts,
 * encrypted JSON payloads) is small and sent as a single complete frame.
 */
public class WebSocketConnection {

    private static final int OP_CONTINUATION = 0x0;
    private static final int OP_TEXT         = 0x1;
    private static final int OP_BINARY       = 0x2;
    private static final int OP_CLOSE        = 0x8;
    private static final int OP_PING         = 0x9;
    private static final int OP_PONG         = 0xA;

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    public final String remoteIp;
    private volatile boolean closed = false;

    public WebSocketConnection(Socket socket, InputStream in, OutputStream out) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.remoteIp = socket.getInetAddress().getHostAddress();
    }

    public void close() {
        if (closed) return;
        closed = true;
        try { socket.close(); } catch (IOException ignored) {}
    }

    public boolean isClosed() { return closed; }

    /** Sends a single, complete binary WebSocket frame. Server frames
     *  are never masked, per RFC 6455. */
    public synchronized void sendBinary(byte[] payload) throws IOException {
        sendFrame(OP_BINARY, payload);
    }

    private void sendFrame(int opcode, byte[] payload) throws IOException {
        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.write(0x80 | opcode); // FIN=1, RSV=0, opcode

        int len = payload.length;
        if (len < 126) {
            frame.write(len); // MASK=0 for server frames
        } else if (len <= 0xFFFF) {
            frame.write(126);
            frame.write((len >>> 8) & 0xFF);
            frame.write(len & 0xFF);
        } else {
            frame.write(127);
            for (int i = 7; i >= 0; i--) frame.write((int) ((long) len >>> (i * 8)) & 0xFF);
        }
        frame.write(payload);

        synchronized (out) {
            out.write(frame.toByteArray());
            out.flush();
        }
    }

    /**
     * Blocks until a complete binary message is received, or returns
     * null on connection close. PING frames are answered with PONG
     * automatically and transparently; CLOSE frames close the
     * connection and return null.
     */
    public byte[] receiveBinary() throws IOException {
        while (true) {
            int first = in.read();
            if (first < 0) return null;
            boolean fin = (first & 0x80) != 0;
            int opcode = first & 0x0F;

            int second = readByteOrThrow();
            boolean masked = (second & 0x80) != 0;
            long len = second & 0x7F;

            if (len == 126) {
                len = ((long) readByteOrThrow() << 8) | readByteOrThrow();
            } else if (len == 127) {
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | readByteOrThrow();
            }

            byte[] maskKey = null;
            if (masked) {
                maskKey = new byte[4];
                readFully(maskKey);
            }

            if (len > Integer.MAX_VALUE - 8) throw new IOException("WebSocket frame too large");
            byte[] payload = new byte[(int) len];
            readFully(payload);

            if (masked) {
                for (int i = 0; i < payload.length; i++) {
                    payload[i] ^= maskKey[i % 4];
                }
            }

            if (!fin) {
                // Fragmented messages aren't supported -- treat as a
                // protocol violation and close, rather than silently
                // returning a truncated/wrong message.
                throw new IOException("Fragmented WebSocket messages not supported");
            }

            switch (opcode) {
                case OP_BINARY, OP_TEXT -> {
                    return payload;
                }
                case OP_CLOSE -> {
                    return null;
                }
                case OP_PING -> sendFrame(OP_PONG, payload);
                case OP_PONG -> { /* ignore */ }
                default -> throw new IOException("Unsupported WebSocket opcode: " + opcode);
            }
        }
    }

    private int readByteOrThrow() throws IOException {
        int b = in.read();
        if (b < 0) throw new EOFException("WebSocket connection closed mid-frame");
        return b;
    }

    private void readFully(byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) throw new EOFException("WebSocket connection closed mid-frame");
            off += n;
        }
    }
}