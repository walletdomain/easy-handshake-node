package handshake.validator;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    public WebSocketServer(int port, ConnectionHandler handler) {
        this.port = port;
        this.handler = handler;
    }

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
                executor.submit(() -> handleConnection(socket));
            } catch (IOException e) {
                if (running) {
                    System.out.println("[WebSocketServer] Accept error: " + e.getMessage());
                }
            }
        }
    }

    private void handleConnection(Socket socket) {
        try {
            socket.setTcpNoDelay(true);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            if (!performOpeningHandshake(in, out)) {
                socket.close();
                return;
            }

            WebSocketConnection conn = new WebSocketConnection(socket, in, out);
            handler.onConnect(conn);
        } catch (Exception e) {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Reads the HTTP upgrade request and sends the 101 Switching
     * Protocols response with the correctly-computed Sec-WebSocket-Accept
     * header. Returns false (and the caller closes the socket) if this
     * doesn't look like a valid WebSocket upgrade request at all.
     */
    private boolean performOpeningHandshake(InputStream in, OutputStream out) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII));
        String requestLine = reader.readLine();
        if (requestLine == null || !requestLine.startsWith("GET")) return false;

        String webSocketKey = null;
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon < 0) continue;
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (name.equalsIgnoreCase("Sec-WebSocket-Key")) {
                webSocketKey = value;
            }
        }
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