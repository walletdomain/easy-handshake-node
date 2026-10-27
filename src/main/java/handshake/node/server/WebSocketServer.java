package handshake.node.server;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A minimal, from-scratch RFC 6455 WebSocket server -- no external
 * dependencies, consistent with the rest of this project. WebSocket
 * itself is a stable, well-documented, Handshake-agnostic public
 * standard (unlike most of this project's other wire formats), so this
 * is implemented directly from the RFC rather than needing any hsd
 * source. The opening-handshake accept-key computation is verified
 * against RFC 6455's own published test vector before being trusted.
 *
 * This class only handles the WebSocket transport/framing layer --
 * accepting connections, completing the opening handshake, and
 * sending/receiving discrete binary messages. The actual security
 * (Brontide handshake + encryption) and application protocol (JSON
 * calls/events) are layered on top, in NodeSocketServer.
 */
public class WebSocketServer {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public interface ConnectionHandler {
        void onConnect(WebSocketConnection conn);
    }

    private final int port;
    private final ConnectionHandler handler;
    private ServerSocket serverSocket;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private volatile boolean running = false;

    private final int maxTotal;
    private final int maxPerIp;
    private final AtomicInteger total = new AtomicInteger();
    private final ConcurrentHashMap<String, AtomicInteger> perIp = new ConcurrentHashMap<>();

    public WebSocketServer(int port, ConnectionHandler handler) {
        this(port, handler, 200, 8);
    }

    public WebSocketServer(int port, ConnectionHandler handler, int maxTotal, int maxPerIp) {
        this.port = port;
        this.handler = handler;
        this.maxTotal = maxTotal;
        this.maxPerIp = maxPerIp;
    }

    /** Takes one slot for this IP; returns a one-shot release, or null if a limit is reached. */
    private Runnable acquireSlot(String ip) {
        if (total.incrementAndGet() > maxTotal) { total.decrementAndGet(); return null; }
        AtomicInteger c = perIp.computeIfAbsent(ip, k -> new AtomicInteger());
        if (c.incrementAndGet() > maxPerIp) {
            c.decrementAndGet();
            total.decrementAndGet();
            return null;
        }
        AtomicBoolean done = new AtomicBoolean();
        return () -> {
            if (!done.compareAndSet(false, true)) return;
            total.decrementAndGet();
            if (c.decrementAndGet() <= 0) perIp.remove(ip, c);
        };
    }

    public int connectionCount() { return total.get(); }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        running = true;
        Thread acceptThread = new Thread(this::acceptLoop, "ws-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public void stop() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        executor.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                Runnable release = acquireSlot(socket.getInetAddress().getHostAddress());
                if (release == null) {
                    try { socket.close(); } catch (IOException ignored) {}
                    continue;
                }
                executor.submit(() -> handleConnection(socket, release));
            } catch (IOException e) {
                if (running) {
                    System.out.println("[WebSocketServer] Accept error: " + e.getMessage());
                    // Retrying instantly on a persistent failure spun at 100% CPU and flooded the log.
                    try { Thread.sleep(250); } catch (InterruptedException ie) { return; }
                }
            }
        }
    }

    private void handleConnection(Socket socket, Runnable release) {
        WebSocketConnection conn = null;
        try {
            socket.setTcpNoDelay(true);
            socket.setKeepAlive(true);
            // A client that connects and never sends its upgrade request must not hold this thread forever.
            socket.setSoTimeout(10_000);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            if (!performOpeningHandshake(in, out)) {
                socket.close();
                return;
            }
            // The upgrade is done: an established session may legitimately sit idle, so lift the timeout.
            // (NodeSocketServer bounds its own Brontide handshake.)
            socket.setSoTimeout(0);

            conn = new WebSocketConnection(socket, in, out);
            conn.setCloseHook(release);
            handler.onConnect(conn);
        } catch (Exception e) {
            try { socket.close(); } catch (IOException ignored) {}
            if (conn != null) conn.close(); else release.run();
        }
    }

    /** Reads one CRLF/LF-terminated header line, at most 2 KB, before the deadline; null on EOF. */
    private static String readHeaderLine(InputStream in, long deadline) throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (System.currentTimeMillis() > deadline) throw new IOException("WebSocket upgrade too slow");
            int b = in.read();
            if (b < 0) return sb.length() == 0 ? null : sb.toString();
            if (b == '\n') {
                int n = sb.length();
                if (n > 0 && sb.charAt(n - 1) == '\r') sb.setLength(n - 1);
                return sb.toString();
            }
            if (sb.length() >= 2048) throw new IOException("WebSocket header line too long");
            sb.append((char) b);
        }
    }

    /**
     * Reads the HTTP upgrade request and sends the 101 Switching
     * Protocols response with the correctly-computed Sec-WebSocket-Accept
     * header. Returns false (and the caller closes the socket) if this
     * doesn't look like a valid WebSocket upgrade request at all.
     */
    private boolean performOpeningHandshake(InputStream in, OutputStream out) throws IOException {
        // Bounded: a line over 2 KB, more than 8 KB of headers, or more than 10 s in total is refused.
        long deadline = System.currentTimeMillis() + 10_000;
        String requestLine = readHeaderLine(in, deadline);
        if (requestLine == null || !requestLine.startsWith("GET")) return false;

        String webSocketKey = null;
        String line;
        int headerBytes = requestLine.length();
        while ((line = readHeaderLine(in, deadline)) != null && !line.isEmpty()) {
            headerBytes += line.length() + 2;
            if (headerBytes > 8192) return false;
            int colon = line.indexOf(':');
            if (colon < 0) continue;
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (name.equalsIgnoreCase("Sec-WebSocket-Key")) {
                webSocketKey = value;
            }
        }
        if (line == null) return false;   // connection ended before the blank line
        if (webSocketKey == null) return false;

        String acceptKey;
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest((webSocketKey + GUID).getBytes(StandardCharsets.US_ASCII));
            acceptKey = Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return false;
        }

        String response = "HTTP/1.1 101 Switching Protocols\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Accept: " + acceptKey + "\r\n"
                + "\r\n";
        out.write(response.getBytes(StandardCharsets.US_ASCII));
        out.flush();
        return true;
    }
}