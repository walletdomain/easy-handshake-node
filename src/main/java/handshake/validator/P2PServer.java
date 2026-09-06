package handshake.validator;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
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

    private final ExecutorService acceptExecutor = Executors.newSingleThreadExecutor(
        r -> namedDaemon(r, "p2p-accept"));
    private final ExecutorService handshakeExecutor = Executors.newCachedThreadPool(
        r -> namedDaemon(r, "p2p-handshake"));

    private ServerSocket serverSocket;

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
        acceptExecutor.submit(this::acceptLoop);
    }

    public synchronized void stop() {
        if (!running.compareAndSet(true, false)) return;
        closeQuietly(serverSocket);
        acceptExecutor.shutdownNow();
        handshakeExecutor.shutdownNow();
    }

    private void acceptLoop() {
        while (running.get()) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running.get()) continue;
                break;
            }
            handshakeExecutor.submit(() -> handleAccepted(socket));
        }
    }

    private void handleAccepted(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();

        if (PeerScorecard.get().shouldSkip(ip)) {
            closeQuietly(socket);
            return;
        }
        if (chainSync.inboundPeerCount() >= config.getMaxInbound()) {
            closeQuietly(socket);
            return;
        }

        boolean established = false;
        try {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            BrontideState brontide = new BrontideState(identity.getPrivateKey());

            byte[] actOne = new byte[BrontideState.ACT_ONE_SIZE];
            in.readFully(actOne);
            brontide.recvActOne(actOne);

            byte[] actTwo = brontide.genActTwo();
            out.write(actTwo);
            out.flush();

            byte[] actThree = new byte[BrontideState.ACT_THREE_SIZE];
            in.readFully(actThree);
            brontide.recvActThree(actThree);

            if (!brontide.isReady()) {
                throw new IOException("Handshake did not complete");
            }

            established = true;
            // registerInboundPeer takes ownership of the socket from here
            // (P2P version handshake + ongoing read loop + scorecard/close).
            chainSync.registerInboundPeer(socket, brontide, ip);

        } catch (Exception e) {
            PeerScorecard.get().recordFailure(ip, "brontide handshake failed: " + e.getMessage());
        } finally {
            if (!established) {
                closeQuietly(socket);
            }
        }
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
