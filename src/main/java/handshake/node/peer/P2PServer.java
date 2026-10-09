package handshake.node.peer;

import handshake.node.chain.ChainSync;
import handshake.node.NodeConfig;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * P2PServer — accepts inbound Brontide connections, performs the real
 * responder-side handshake (Act 1 -> Act 2 -> Act 3, per BrontideState),
 * and hands the established connection to
 * {@link ChainSync#registerInboundPeer}, which takes over for the P2P
 * version handshake and ongoing message loop.
 * <p>
 * Enforces {@link NodeConfig#getMaxInbound()} against ChainSync's live
 * peer count (not a locally-tracked counter -- see git history for why
 * that approach doesn't reflect reality once a handshake actually
 * completes) and skips addresses {@link PeerScorecard} currently has
 * backed off.
 */
public class P2PServer {

    private final NodeConfig config;
    private final NodeIdentity identity;
    private final ChainSync chainSync;

    private final AtomicBoolean running = new AtomicBoolean(false);

    private final ExecutorService acceptExecutor = Executors.newFixedThreadPool(2,
            r -> namedDaemon(r, "p2p-accept"));
    private final ExecutorService handshakeExecutor = Executors.newCachedThreadPool(
            r -> namedDaemon(r, "p2p-handshake"));

    private ServerSocket serverSocket;
    private ServerSocket plainServerSocket;   // cleartext listener (hsd's standard port), may be null

    public P2PServer(NodeConfig config, NodeIdentity identity, ChainSync chainSync) {
        this.config = config;
        this.identity = identity;
        this.chainSync = chainSync;
    }

    public synchronized void start() throws IOException {
        if (!running.compareAndSet(false, true)) return;
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(config.getP2pPort()));
        acceptExecutor.submit(() -> acceptLoop(serverSocket, false));

        // Cleartext listener: plain hsd peers can connect to us the way they
        // connect to each other. A failure to bind it (port in use, no
        // permission) must not take down the Brontide listener.
        if (config.isPlainP2pEnabled()) {
            try {
                plainServerSocket = new ServerSocket();
                plainServerSocket.setReuseAddress(true);
                plainServerSocket.bind(new InetSocketAddress(config.getPlainP2pPort()));
                final ServerSocket plainSock = plainServerSocket;
                acceptExecutor.submit(() -> acceptLoop(plainSock, true));
                System.out.printf("[P2PServer] Cleartext listener on port %d (peers connecting here are scored as downgraded cleartext peers).%n",
                        config.getPlainP2pPort());
            } catch (IOException e) {
                System.out.printf("[P2PServer] Could not open cleartext listener on port %d: %s -- continuing Brontide-only.%n",
                        config.getPlainP2pPort(), e.getMessage());
                closeQuietly(plainServerSocket);
                plainServerSocket = null;
            }
        }
    }

    public synchronized void stop() {
        if (!running.compareAndSet(true, false)) return;
        closeQuietly(serverSocket);
        closeQuietly(plainServerSocket);
        acceptExecutor.shutdownNow();
        handshakeExecutor.shutdownNow();
    }

    private void acceptLoop(ServerSocket listener, boolean plain) {
        while (running.get()) {
            Socket socket;
            try {
                socket = listener.accept();
            } catch (IOException e) {
                if (running.get() && !listener.isClosed()) continue;
                break;
            }
            handshakeExecutor.submit(() -> {
                if (plain) handleAcceptedPlain(socket); else handleAccepted(socket);
            });
        }
    }

    /** Inbound cleartext connection: no Brontide handshake, straight to the
     *  P2P version handshake. Same skip/limit rules as the Brontide path. */
    private void handleAcceptedPlain(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        System.out.printf("[P2PServer] Inbound CLEARTEXT connection attempt from %s%n", ip);
        // Only an explicit ban blocks an inbound peer. Backoff records OUR failures
        // dialing THEM; it says nothing about whether they may dial us.
        if (PeerTable.get().isBanned(ip)) {
            System.out.printf("[P2PServer] Rejected inbound cleartext from %s -- banned.%n", ip);
            closeQuietly(socket);
            return;
        }
        if (chainSync.inboundPeerCount() >= config.getMaxInbound()) {
            System.out.printf("[P2PServer] Rejected inbound cleartext from %s -- at max inbound (%d).%n",
                    ip, config.getMaxInbound());
            closeQuietly(socket);
            return;
        }
        // registerInboundPeer takes ownership of the socket (and closes it on failure).
        chainSync.registerInboundPeer(socket, null, ip);
    }

    private void handleAccepted(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        // DIAGNOSTIC: this entire method previously had NO logging at
        // all -- not for a raw accept, not for a rejected/skipped
        // connection, not even for a failed handshake (the catch below
        // only ever wrote to PeerScorecard, never printed anything).
        // Every single inbound connection attempt, successful or not,
        // was completely invisible in the console/log output. That's
        // indistinguishable from "nothing ever tried to connect" even
        // when something genuinely did, and is why there was no way to
        // confirm or refute inbound activity just from reading output
        // -- this one line alone answers that going forward.
        System.out.printf("[P2PServer] Inbound connection attempt from %s%n", ip);

        // See handleAcceptedPlain(): backoff must not block inbound; only a ban does.
        if (PeerTable.get().isBanned(ip)) {
            System.out.printf("[P2PServer] Rejected inbound from %s -- banned.%n", ip);
            closeQuietly(socket);
            return;
        }
        if (chainSync.inboundPeerCount() >= config.getMaxInbound()) {
            System.out.printf("[P2PServer] Rejected inbound from %s -- at max inbound (%d).%n",
                    ip, config.getMaxInbound());
            closeQuietly(socket);
            return;
        }

        boolean established = false;
        try {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            BrontideState brontide = new BrontideState(identity.getPrivateKey());

            // DIAGNOSTIC (lowest level available short of an OS-level packet
            // capture): readPartialDebug(), not a plain readFully(), so a
            // connection that sends nothing, sends garbage, or disconnects
            // mid-read is still visible -- byte count and raw hex of
            // whatever actually arrived -- instead of collapsing straight
            // to "EOFException" with nothing to show for it. Gated behind
            // ChainSync.VERBOSE_WIRE_LOGGING (same switch the outbound side
            // already uses) so a normal run stays quiet; flip that one flag
            // to see every raw inbound handshake byte, on both sides, at once.
            byte[] actOne = readPartialDebug(in, BrontideState.ACT_ONE_SIZE, ip, "Act One");
            brontide.recvActOne(actOne);

            byte[] actTwo = brontide.genActTwo();
            out.write(actTwo);
            out.flush();

            byte[] actThree = readPartialDebug(in, BrontideState.ACT_THREE_SIZE, ip, "Act Three");
            brontide.recvActThree(actThree);

            if (!brontide.isReady()) {
                throw new IOException("Handshake did not complete");
            }

            established = true;
            System.out.printf("[P2PServer] Inbound Brontide handshake complete with %s%n", ip);
            // registerInboundPeer takes ownership of the socket from here
            // (P2P version handshake + ongoing read loop + scorecard/close).
            chainSync.registerInboundPeer(socket, brontide, ip);

        } catch (Exception e) {
            // DIAGNOSTIC: previously silent -- only recorded to
            // PeerScorecard, which is backoff bookkeeping, not visible
            // output. A failing inbound handshake and zero inbound
            // attempts at all looked identical in the console; now they
            // don't.
            System.out.printf("[P2PServer] Inbound handshake with %s failed: %s: %s%n",
                    ip, e.getClass().getSimpleName(), e.getMessage());
            PeerTable.get().recordFailure(ip, "brontide handshake failed: " + e.getMessage());
        } finally {
            if (!established) {
                closeQuietly(socket);
            }
        }
    }

    /**
     * Reads exactly {@code len} bytes, like DataInputStream.readFully(),
     * but (a) always logs -- gated behind ChainSync.VERBOSE_WIRE_LOGGING --
     * exactly how many bytes arrived and their raw hex, even on a short
     * read, and (b) throws a real EOFException naming the actual byte
     * count on a short read instead of readFully()'s own message, which
     * says nothing about what, if anything, was received. Mirrors
     * PeerConnection.readPartialDebug() on the outbound side (same project,
     * same reasoning -- see its own comment: a bare "timeout"/"EOF" with no
     * byte count is exactly what hid the real handshake bugs this project
     * spent a long time chasing earlier).
     */
    private static byte[] readPartialDebug(InputStream in, int len, String ip, String label) throws IOException {
        byte[] buf = new byte[len];
        int read = 0;
        try {
            while (read < len) {
                int n = in.read(buf, read, len - read);
                if (n < 0) break;
                read += n;
            }
        } catch (IOException e) {
            if (ChainSync.VERBOSE_WIRE_LOGGING) {
                System.out.printf("[P2PServer] <- %s %s read error after %d/%d bytes: %s: %s%n",
                        ip, label, read, len, e.getClass().getSimpleName(), e.getMessage());
            }
            throw e;
        }
        if (ChainSync.VERBOSE_WIRE_LOGGING) {
            System.out.printf("[P2PServer] <- %s %s: got %d/%d bytes: %s%n",
                    ip, label, read, len, toHex(Arrays.copyOf(buf, read)));
        }
        if (read < len) {
            throw new EOFException(label + ": got only " + read + "/" + len + " bytes");
        }
        return buf;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static void closeQuietly(java.io.Closeable c) {
        try { if (c != null) c.close(); } catch (IOException ignored) { }
    }

    private static Thread namedDaemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }
}