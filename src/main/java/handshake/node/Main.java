package handshake.node;

import java.awt.Desktop;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;

/**
 * Main — entry point for the Handshake validator validator.
 * <p>
 * Startup sequence:
 *   1. Load config (validator.conf)
 *   2. Open chain database (chain.mv.db)
 *   3. Load validator identity (validator.key)
 *   4. Initialize peer scorecard
 *   5. Start RPC server (JSON-RPC + WebSocket)
 *   6. Start P2P server (accept inbound Brontide connections)
 *   7. Start chain sync (header sync + block download + peer discovery)
 * <p>
 * Usage:
 *   java -jar easy-handshake-validator.jar [data-dir]
 * <p>
 * Default data directory: a ".easy-handshake" folder created next to the
 * jar file itself (not the current working directory -- those aren't
 * always the same thing depending on how the jar is launched). On first
 * run this folder doesn't exist yet and gets created along with fresh
 * H2 database files inside it; on later runs its presence is exactly what
 * signals "not a fresh install" and the existing databases get reopened.
 */
public class Main {

    // Held for the entire process lifetime -- releasing (or garbage
    // collecting) either of these would release the lock, so both are
    // kept as static fields rather than local variables that could, in
    // principle, become eligible for GC despite main() never returning.
    private static RandomAccessFile instanceLockFile;
    private static FileChannel instanceLockChannel;

    static void main(String[] args) throws Exception {
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║   Easy Handshake Node  v0.1.0        ║");
        System.out.println("║   Handshake Validator Node           ║");
        System.out.println("╚══════════════════════════════════════╝");

        // ── 1. Data directory ─────────────────────────────────────────────────
        String dataDir = args.length > 0 ? args[0] : defaultDataDir();
        boolean freshInstall = !Files.exists(Path.of(dataDir));
        Files.createDirectories(Path.of(dataDir));
        System.out.println("[Main] Data directory: " + Path.of(dataDir).toAbsolutePath()
                + (freshInstall ? " (fresh install)" : ""));

        // ── 1b. Single-instance check ────────────────────────────────────────
        // Deliberately before any slow or lockable resource (config,
        // chain database) gets touched at all: if another instance is
        // already running, this should be fast and clean -- just open a
        // browser tab to the existing instance and exit quietly, not
        // race the real instance for the database and fail with a raw
        // lock-conflict exception. A dedicated lock file (not the
        // database itself) keeps this check independent of anything
        // else that could be slow to open.
        acquireInstanceLockOrRedirectAndExit(dataDir);

        // ── 2. Configuration ──────────────────────────────────────────────────
        NodeConfig config = NodeConfig.load(dataDir);
        System.out.println("[Main] Config: " + config);

        // Generate a real API key on first run -- setApiKey() previously
        // existed but was never actually called anywhere, meaning
        // hasApiKey() was always false. Printed once, matching the
        // existing pattern for the node's own identity key; also
        // viewable afterward on the (loopback-only) admin page.
        if (!config.hasApiKey()) {
            byte[] keyBytes = new byte[24];
            new java.security.SecureRandom().nextBytes(keyBytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : keyBytes) sb.append(String.format("%02x", b));
            String generatedKey = sb.toString();
            config.setApiKey(generatedKey);
            System.out.println("[Main] Generated new RPC API key: " + generatedKey);
        }

        // ── 3. Chain database ─────────────────────────────────────────────────
        String dbPath = dataDir + "/chain.mv.db";
        ChainDB db = ChainDB.open(dbPath);
        System.out.printf("[Main] Chain DB opened: %s (%.1f GB)%n",
                dbPath, db.getDiskSizeBytes() / 1e9);
        System.out.printf("[Main] Headers: ~%d  Blocks: ~%d  UTXOs: ~%d  Names: ~%d%n",
                db.getHeaderCountEstimate(), db.getBlockCountEstimate(),
                db.getUtxoCountEstimate(), db.getNameCountEstimate());
        db.backfillHashIndexIfNeeded();

        // ── 4. Node identity (Brontide keypair) ───────────────────────────────
        NodeIdentity identity = NodeIdentity.load(dataDir);

        // ── 5. Peer scorecard ─────────────────────────────────────────────────
        PeerScorecard.get().init(ConfigDB.get());
        PeerDiscovery.get().init(db);

        // ── 6. Seed database ──────────────────────────────────────────────────
        SeedDatabase seeds = SeedDatabase.get();
        System.out.printf("[Main] Seeds loaded: %d Brontide, %d cleartext%n",
                seeds.getBrontideSeeds().size(),
                seeds.getCleartextSeeds().size());

        // ── 7. RPC server ─────────────────────────────────────────────────────
        RpcServer rpc = new RpcServer(config, db);
        rpc.start();
        System.out.printf("[Main] RPC server: http://%s:%d%n",
                config.getRpcHost(), config.getRpcPort());

        // ── 7b. Web admin server (localhost-only) ────────────────────────────
        WebAdminServer webAdmin = new WebAdminServer(config, db);
        webAdmin.start();
        System.out.printf("[Main] Web admin: http://127.0.0.1:%d%n",
                config.getWebAdminPort());
        writePortFile(dataDir, config.getWebAdminPort());
        openBrowser("http://localhost:" + config.getWebAdminPort());

        // ── 8. Chain sync ──────────────────────────────────────────────────────
        // (constructed before P2PServer since P2PServer hands off completed
        // inbound handshakes to it directly)
        ChainSync sync = new ChainSync(config, db, identity, rpc);
        webAdmin.setChainSync(sync);
        // FIX: this call was missing entirely -- RpcServer.chainSync
        // stayed null for the node's whole lifetime, meaning every RPC
        // method depending on it silently fell back to its "no
        // ChainSync" default instead of throwing or warning about it.
        // Confirmed as the real cause of a genuine, reported bug
        // (getpeerinfo always returning an empty array despite the
        // node actively syncing) -- and, worse, also the cause of
        // getblockchaininfo's "verificationprogress" always reporting
        // exactly 1.0 (100%), from block zero onward: with chainSync
        // null, chainPeerHeight silently fell back to our OWN tip
        // instead of the real, known peer height, making the
        // tip/chainPeerHeight division always compute to tip/tip = 1.0
        // regardless of actual sync progress.
        rpc.setChainSync(sync);
        sync.start();
        System.out.println("[Main] Chain sync started.");

        // ── 8b. Mempool ───────────────────────────────────────────────────────
        // Previously never constructed anywhere in this project despite all
        // the work done on Mempool.java itself (signature verification,
        // relay, etc.) -- every "if (mempool != null)" check throughout the
        // codebase was silently false at runtime, meaning sendrawtransaction,
        // peer transaction relay, and every mempool-related RPC method were
        // all inert. Wiring it into both ChainSync (for P2P relay) and
        // RpcServer (for sendrawtransaction/getrawmempool/etc.) is what
        // actually makes all of that real.
        Mempool mempool = new Mempool(db);
        webAdmin.setMempool(mempool);

        // ── 8c. Node socket server (Brontide-over-WebSocket, Bloom-filtered) ────
        NodeSocketServer socketServer = new NodeSocketServer(config, db, identity, sync);
        socketServer.setMempool(mempool);
        socketServer.registerWithRpc(rpc);
        socketServer.start();
        sync.setMempool(mempool);
        rpc.setMempool(mempool);
        System.out.println("[Main] Mempool initialized.");

        // ── 9. P2P inbound server ─────────────────────────────────────────────
        P2PServer p2p = new P2PServer(config, identity, sync);
        p2p.start();
        System.out.printf("[Main] P2P server listening on port %d%n",
                config.getP2pPort());

        // Peer discovery (GETADDR after every connection, real ADDR
        // parsing, weighted candidate selection) is now handled directly
        // by ChainSync itself -- the separate PeerCrawler class that used
        // to run alongside it has been removed. It duplicated this same
        // responsibility with an older, incompatible message-framing
        // implementation that predated the fixes ChainSync now has.

        // ── Shutdown hook ─────────────────────────────────────────────────────
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[Main] Shutting down...");
            // FIX: each step is now independently guarded. Previously an
            // exception anywhere in this sequence (confirmed via a real
            // crash: db.commit() threw ClosedChannelException after a
            // forced-shutdown race) silently aborted every step after
            // it -- db.close(), ConfigDB.get().commit(), and
            // ConfigDB.get().close() never ran at all, leaving the
            // config database un-flushed and both databases un-closed
            // on top of whatever triggered the original failure. Each
            // step now runs regardless of whether an earlier one
            // failed, and any failure is reported rather than silently
            // swallowed.
            safeShutdownStep("sync.stop", sync::stop);
            safeShutdownStep("p2p.stop", p2p::stop);
            safeShutdownStep("rpc.stop", rpc::stop);
            safeShutdownStep("webAdmin.stop", webAdmin::stop);
            safeShutdownStep("socketServer.stop", socketServer::stop);
            safeShutdownStep("db.commit", db::commit);
            safeShutdownStep("db.close", db::close);
            safeShutdownStep("ConfigDB.commit", () -> ConfigDB.get().commit());
            safeShutdownStep("ConfigDB.close", () -> ConfigDB.get().close());
            System.out.println("[Main] Shutdown complete.");
        }, "shutdown-hook"));

        System.out.println("[Main] Node started. Press Ctrl+C to stop.");

        // Keep main thread alive
        Thread.currentThread().join();
    }

    /**
     * Resolves ".easy-handshake" next to the actual running jar file, not
     * relative to the current working directory. Falls back to a relative
     * "./.easy-handshake" if the jar's own location can't be determined
     * (e.g. running exploded classes from an IDE rather than a real jar).
     */
    /**
     * Tries to acquire an exclusive lock on a small, dedicated lock file
     * (not the database itself) as the very first thing this process
     * does with the data directory. If another instance already holds
     * it, this one is the "user double-clicked the exe while it was
     * already running" case -- redirect to the existing instance's
     * admin page and exit cleanly, rather than proceeding to race the
     * real instance for the database and crash with a raw lock
     * exception. If this DOES acquire the lock, it stays held (via the
     * static fields above) for the rest of the process's life.
     */
    private static void acquireInstanceLockOrRedirectAndExit(String dataDir) throws IOException {
        Path lockPath = Path.of(dataDir, "instance.lock");
        instanceLockFile = new RandomAccessFile(lockPath.toFile(), "rw");
        instanceLockChannel = instanceLockFile.getChannel();

        FileLock lock;
        try {
            lock = instanceLockChannel.tryLock();
        } catch (Exception e) {
            lock = null;
        }

        if (lock == null) {
            int port = readPortFileOrDefault(dataDir);
            System.out.println("[Main] Already running -- opening browser to "
                    + "http://localhost:" + port + " and exiting.");
            openBrowser("http://localhost:" + port);
            System.exit(0);
        }
    }

    /** Best-effort: not every environment supports this (a headless VPS,
     *  for instance, which this same project also legitimately runs on)
     *  -- fails gracefully with a plain printed URL rather than crashing
     *  the whole startup over something this non-essential. */
    private static void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
                return;
            }
        } catch (Exception ignored) {
            // fall through to the manual-open message below
        }
        System.out.println("[Main] Could not auto-open a browser -- please open manually: " + url);
    }

    private static int readPortFileOrDefault(String dataDir) {
        try {
            return Integer.parseInt(Files.readString(Path.of(dataDir, "webadmin.port")).trim());
        } catch (Exception e) {
            return 12080; // matches NodeConfig's own DEFAULT_WEB_ADMIN_PORT
        }
    }

    private static void writePortFile(String dataDir, int port) throws IOException {
        Files.writeString(Path.of(dataDir, "webadmin.port"), String.valueOf(port));
    }

    private static String defaultDataDir() {
        // FIX: previously always resolved to the user's home directory,
        // regardless of where the jar itself was run from. That's the
        // right choice when the jar lives somewhere that might not be
        // writable (e.g. a system-protected install location), which is
        // exactly why this was moved away from resolving relative to
        // the jar/classes location in the first place.
        //
        // But it also meant there was no way to make a node default to
        // storing its (potentially very large -- tens of GB even this
        // early in the chain) database next to a deliberately-chosen
        // location, like a NAS or LAN drive, without an explicit
        // command-line argument every single run. If the person places
        // and runs the jar itself from such a location on purpose, the
        // data belongs right there by default.
        //
        // So: prefer a .easy-handshake folder next to the running
        // jar/classes, but only if that location is actually writable
        // right now -- falling back to the home directory otherwise,
        // preserving the original robustness this code was written for.
        // This keeps the explicit command-line argument (see main()'s
        // args[0] handling, a few lines up) as the one, already-existing
        // way to fully override the location regardless of where the
        // jar lives.
        String jarAdjacent = jarAdjacentDataDir();
        if (jarAdjacent != null && isWritableDataDir(jarAdjacent)) {
            return jarAdjacent;
        }
        return Path.of(System.getProperty("user.home"), ".easy-handshake").toString();
    }

    /** Returns a .easy-handshake path next to the running jar (or, in a
     *  dev/IDE run, next to the compiled classes root), or null if that
     *  location can't be determined at all -- some launch mechanisms
     *  (certain application-packaging tools, some test runners) don't
     *  expose a usable code source location, and falling back cleanly
     *  is far better than failing startup over it. */
    private static String jarAdjacentDataDir() {
        try {
            java.net.URI codeLocation = Main.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI();
            Path codePath = Path.of(codeLocation);
            // A packaged jar's code source IS the jar file itself, so
            // its parent is the containing folder. A dev/IDE run's code
            // source is the classes ROOT DIRECTORY (e.g. target/classes)
            // itself, which is already the directory we want -- no
            // extra parent step there, or this would land one level too
            // high (in target/ instead of alongside the actual run).
            Path containingDir = Files.isDirectory(codePath) ? codePath : codePath.getParent();
            if (containingDir == null) return null;
            return containingDir.resolve(".easy-handshake").toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** Checks whether a data directory is actually usable right now --
     *  by creating it (mkdirs is a no-op if it already exists) and
     *  writing then deleting a small marker file, rather than trusting
     *  any weaker signal. This is deliberately conservative: a NAS
     *  that's temporarily unreachable, a read-only mount, or a
     *  permissions issue should all cleanly fall back to the home
     *  directory rather than fail startup outright. */
    private static boolean isWritableDataDir(String dir) {
        try {
            Path dirPath = Path.of(dir);
            Files.createDirectories(dirPath);
            Path marker = dirPath.resolve(".write-test");
            Files.writeString(marker, "");
            Files.delete(marker);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Runs one shutdown step in isolation -- a failure here is reported
     *  but never prevents the remaining steps from running. See the
     *  shutdown hook's own comment for why this matters: a single
     *  uncaught exception used to silently abort everything after it,
     *  including steps (like ConfigDB's own commit/close) with no
     *  relation to whatever failed first. */
    private static void safeShutdownStep(String label, ShutdownStep step) {
        try {
            step.run();
        } catch (Throwable t) {
            System.err.println("[Main] Shutdown step '" + label + "' failed (continuing "
                    + "with remaining shutdown steps regardless): " + t);
        }
    }

    @FunctionalInterface
    private interface ShutdownStep {
        void run() throws Exception;
    }
}