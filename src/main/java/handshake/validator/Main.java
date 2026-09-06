package handshake.validator;

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
        System.out.printf("[Main] Headers: %d  Blocks: %d  UTXOs: %d  Names: %d%n",
                db.getHeaderCount(), db.getBlockCount(),
                db.getUtxoCount(), db.getNameCount());
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

        // ── 8. Chain sync ──────────────────────────────────────────────────────
        // (constructed before P2PServer since P2PServer hands off completed
        // inbound handshakes to it directly)
        ChainSync sync = new ChainSync(config, db, identity, rpc);
        webAdmin.setChainSync(sync);
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
            sync.stop();
            p2p.stop();
            rpc.stop();
            webAdmin.stop();
            db.commit();
            db.close();
            ConfigDB.get().commit();
            ConfigDB.get().close();
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
    private static String defaultDataDir() {
        try {
            Path jarPath = Path.of(
                    Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            Path jarDir = Files.isDirectory(jarPath) ? jarPath : jarPath.getParent();
            if (jarDir != null) {
                return jarDir.resolve(".easy-handshake").toString();
            }
        } catch (Exception ignored) {
            // Fall through to the relative default below.
        }
        return "./.easy-handshake";
    }
}