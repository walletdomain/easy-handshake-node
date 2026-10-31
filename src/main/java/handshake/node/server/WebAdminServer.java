package handshake.node.server;

import handshake.node.util.HexUtil;
import handshake.node.util.JsonUtil;

import handshake.node.storage.ChainDB;

import handshake.node.urkeltree.UrkelTreeMismatchException;

import handshake.node.peer.PeerTable;

import handshake.node.chain.ChainSync;
import handshake.node.chain.Mempool;
import handshake.node.NodeConfig;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A lightweight, localhost-only admin web server for the validator --
 * serves the static HTML/CSS/JS content in WebAdminServerContent, plus
 * a small JSON API for viewing/changing configuration and viewing the
 * RPC API key. No TLS: the security boundary here isn't encryption,
 * it's that the socket is bound directly to the loopback interface,
 * not a configurable or wildcard address, so no remote machine can
 * reach it regardless of firewall rules or any application-level
 * logic. Reuses com.sun.net.httpserver.HttpServer -- the same class
 * RpcServer already uses successfully -- rather than introducing any
 * new HTTP transport.
 *
 * Loopback binding alone doesn't fully cover state-changing requests,
 * though: a malicious page open in another browser tab on the same
 * machine can still silently submit a POST to a known local port (a
 * "local CSRF" pattern) -- loopback binding stops remote attackers, not
 * this. POST /api/config therefore also requires the request's Origin
 * header to match this server's own origin; GET requests have no side
 * effects and aren't restricted this way.
 *
 * The event/socket channels planned for later are still not part of
 * this.
 */
public class WebAdminServer {

    /** Only settings that actually do something right now are editable
     *  here -- max.outbound, index.address, and log.level are all
     *  currently stored but not consulted by anything in the codebase,
     *  so exposing them as "editable" would silently mislead: they'd
     *  appear to save successfully while having zero real effect.
     *  "network" and "index.tx" used to be here too -- see
     *  NodeConfig.getNetwork()/indexTx()'s own comments for why they're
     *  now hardcoded rather than editable at all.
     *
     *  FIX: "p2p.port" and "rpc.port" removed from here too, at the
     *  person's own request -- both are above 1024 (no elevated
     *  privileges needed), neither collides with any other common
     *  software, and both are this project's fixed, standard ports for
     *  Handshake P2P and RPC traffic specifically. There's no real
     *  scenario where a newcomer benefits from changing either, and
     *  every scenario where doing so by accident (a typo, a
     *  misunderstanding) quietly breaks connectivity in a confusing
     *  way. Enforced here, not just by removing the form fields in
     *  WebAdminServerContent's HTML/JS -- a direct POST to this
     *  endpoint attempting either key is rejected the same way an
     *  unknown key already is, so the UI omission is a real guarantee,
     *  not just a suggestion. rpc.host stays editable (a genuine,
     *  occasionally useful setting, e.g. binding somewhere other than
     *  loopback for a deliberate remote-RPC setup). */
    private static final Set<String> EDITABLE_KEYS = Set.of(
            "rpc.host", "miner.address", "socket.public"
    );

    private static final Set<String> REQUIRES_RESTART = Set.of(
            "rpc.host"
    );

    private final NodeConfig config;
    private final ChainDB db;
    private final long startTimeMillis = System.currentTimeMillis();
    private final handshake.node.util.SystemMetrics metrics;
    private volatile ChainSync chainSync;
    private volatile Mempool mempool;
    private HttpServer server;
    // Cached (not fixed) pool: each open live-stream page holds one thread for as long as it stays open
    // (capped by MAX_STREAMS); ordinary requests are short and need only a thread for an instant.
    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "web-admin");
        t.setDaemon(true);
        return t;
    });

    public WebAdminServer(NodeConfig config, ChainDB db) {
        this.config = config;
        this.db = db;
        this.metrics = new handshake.node.util.SystemMetrics(config.getDataDir());
        this.storage = new handshake.node.storage.StorageBreakdown(db, config.getDataDir());
    }

    private final handshake.node.storage.StorageBreakdown storage;

    public void setChainSync(ChainSync chainSync) { this.chainSync = chainSync; }
    public void setMempool(Mempool mempool) { this.mempool = mempool; }

    public void start() throws IOException {
        InetSocketAddress addr = new InetSocketAddress(
                InetAddress.getLoopbackAddress(), config.getWebAdminPort());
        server = HttpServer.create(addr, 16);
        server.createContext("/", ex -> serveStatic(ex, "text/html; charset=utf-8", WebAdminServerContent.INDEX_HTML));
        server.createContext("/style.css", ex -> serveStatic(ex, "text/css; charset=utf-8", WebAdminServerContent.STYLE_CSS));
        server.createContext("/app.js", ex -> serveStatic(ex, "application/javascript; charset=utf-8", WebAdminServerContent.APP_JS));
        server.createContext("/api/config", guarded(this::handleConfig));
        server.createContext("/api/apikey", this::handleApiKey);
        server.createContext("/api/status", this::handleStatus);
        server.createContext("/api/peers", guarded(this::handlePeers));
        server.createContext("/api/peertable", guarded(this::handlePeerTable));
        server.createContext("/api/mempool", this::handleMempool);
        server.createContext("/api/bans", guarded(this::handleBans));
        server.createContext("/api/bans/unban", guarded(this::handleUnban));
        server.createContext("/api/bans/clear", guarded(this::handleClearBans));
        server.createContext("/api/stop", this::handleStop);
        server.createContext("/api/rpc", guarded(this::handleRpcProxy));
        server.createContext("/api/events", this::handleEvents);
        server.createContext("/api/log", this::handleLog);
        server.createContext("/api/shutdown", this::handleShutdownState);
        server.setExecutor(executor);
        server.start();
        startPusher();
    }

    public void stop() {
        pusherRunning = false;
        if (server != null) server.stop(1);
        executor.shutdown();
    }

    // ── Shutdown reporting ───────────────────────────────────────────────────
    //
    // The node's shutdown hook keeps this server running to the very end, so a page can show progress and then
    // "safe to power off" only once everything else (including the database close) has really finished.
    // From shutdownBegin() on, nothing here touches the databases any more: status and peers are served from
    // what was built just before, and anything that would need the databases answers 503.

    private volatile String shutdownPhase;          // null = running normally, "running", "complete"
    private volatile String shutdownStep = "";
    private volatile long shutdownStartedAt;
    private volatile String lastStatusJson, lastPeersPushJson;

    /** Call first thing in the shutdown hook, while the databases are still open. */
    public void shutdownBegin() {
        try { lastStatusJson = buildStatusJson(); lastPeersPushJson = buildPeerTableJson(true); } catch (RuntimeException ignored) { /* keep older cache */ }
        shutdownStartedAt = System.currentTimeMillis();
        shutdownPhase = "running";
        broadcast("shutdown", shutdownJson());
    }

    /** Announces the step about to run. */
    public void shutdownStep(String label) {
        shutdownStep = label;
        if (shutdownPhase != null) broadcast("shutdown", shutdownJson());
    }

    /** Call after the last real step; waits (briefly) until open pages have received the message. */
    public void shutdownComplete() {
        shutdownStep = "";
        shutdownPhase = "complete";
        broadcast("shutdown", shutdownJson());
        long deadline = System.currentTimeMillis() + 2500;
        try {
            while (System.currentTimeMillis() < deadline) {
                boolean pending = false;
                for (LiveClient c : clients) if (!c.closed && !c.queue.isEmpty()) pending = true;
                if (!pending) break;
                Thread.sleep(50);
            }
            Thread.sleep(300);                      // let the last write reach the browser
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String shutdownJson() {
        String ph = shutdownPhase;
        return "{\"phase\":" + (ph == null ? "null" : "\"" + ph + "\"")
                + ",\"step\":\"" + jsonEscape(shutdownStep) + "\",\"startedAt\":" + shutdownStartedAt + "}";
    }

    private void handleShutdownState(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) { ex.sendResponseHeaders(405, -1); return; }
            respondJson(ex, 200, shutdownJson());
        } finally {
            ex.close();
        }
    }

    /** Wraps a handler that needs the databases: during shutdown it answers 503 instead. */
    private com.sun.net.httpserver.HttpHandler guarded(com.sun.net.httpserver.HttpHandler h) {
        return ex -> {
            if (shutdownPhase != null) {
                try { respondJson(ex, 503, "{\"error\":\"The node is shutting down\"}"); } finally { ex.close(); }
                return;
            }
            h.handle(ex);
        };
    }

    // ── Live stream (Server-Sent Events) ─────────────────────────────────────
    //
    // One long-lived GET /api/events per open page. The node pushes: "status" (height, sync, system
    // gauges, halt) at most twice a second, "peers" and "mempool" only when their content changed,
    // and every log line as it is printed ("log"; the buffered backlog comes first as "logs").
    // Nothing is computed while no page is open.

    private static final int MAX_STREAMS = 6;
    private final java.util.List<LiveClient> clients = new java.util.concurrent.CopyOnWriteArrayList<>();
    private volatile boolean pusherRunning;
    private String lastPeersJson = "", lastMempoolJson = "";

    private static final class LiveClient {
        final java.util.concurrent.LinkedBlockingQueue<String> queue = new java.util.concurrent.LinkedBlockingQueue<>(2000);
        volatile boolean closed;
        /** Drops the event rather than blocking the pusher when a page is too slow to keep up. */
        void send(String event, String data) { queue.offer("event: " + event + "\ndata: " + data + "\n\n"); }
    }

    private void broadcast(String event, String data) {
        for (LiveClient c : clients) c.send(event, data);
    }

    private void startPusher() {
        pusherRunning = true;
        handshake.node.util.LogTap.addListener(line -> {
            if (!clients.isEmpty()) broadcast("log", line.toJson());
        });
        Thread t = new Thread(() -> {
            int lastHeight = Integer.MIN_VALUE;
            long lastStatus = 0, lastSlow = 0;
            while (pusherRunning) {
                try { Thread.sleep(250); } catch (InterruptedException e) { return; }
                if (shutdownPhase != null) continue;   // the databases are closing: no more reads from the pusher
                if (clients.isEmpty()) { lastPeersJson = ""; lastMempoolJson = ""; lastHeight = Integer.MIN_VALUE; continue; }
                try {
                    long now = System.currentTimeMillis();
                    int height = db.getBlockTip();
                    if ((height != lastHeight && now - lastStatus >= 500) || now - lastStatus >= 1000) {
                        lastHeight = height;
                        lastStatus = now;
                        broadcast("status", buildStatusJson());
                    }
                    if (now - lastSlow >= 1000) {
                        lastSlow = now;
                        String peers = buildPeerTableJson(true);
                        if (!peers.equals(lastPeersJson)) { lastPeersJson = peers; broadcast("peers", peers); }
                        String mp = buildMempoolJson();
                        if (!mp.equals(lastMempoolJson)) { lastMempoolJson = mp; broadcast("mempool", mp); }
                    }
                } catch (Throwable e) {
                    System.err.println("[WebAdmin] live push failed (will retry): " + e);
                }
            }
        }, "web-admin-pusher");
        t.setDaemon(true);
        t.start();
    }

    private void handleEvents(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("GET")) { ex.sendResponseHeaders(405, -1); ex.close(); return; }
        if (clients.size() >= MAX_STREAMS) {
            respondJson(ex, 503, "{\"error\":\"Too many open admin pages\"}");
            ex.close();
            return;
        }
        LiveClient c = new LiveClient();
        ex.getResponseHeaders().add("Content-Type", "text/event-stream; charset=utf-8");
        ex.getResponseHeaders().add("Cache-Control", "no-cache");
        ex.sendResponseHeaders(200, 0);                       // 0 = chunked, stays open
        try (OutputStream os = ex.getResponseBody()) {
            // Everything the page needs to draw itself, straight away.
            StringBuilder logs = new StringBuilder("[");
            boolean first = true;
            for (handshake.node.util.LogTap.Line l : handshake.node.util.LogTap.snapshot()) {
                if (!first) logs.append(",");
                first = false;
                logs.append(l.toJson());
            }
            logs.append("]");
            c.send("logs", logs.toString());
            c.send("status", buildStatusJson());
            c.send("peers", buildPeerTableJson(true));
            c.send("mempool", buildMempoolJson());
            if (shutdownPhase != null) c.send("shutdown", shutdownJson());
            clients.add(c);
            try {
                while (!c.closed && pusherRunning) {
                    String msg = c.queue.poll(15, java.util.concurrent.TimeUnit.SECONDS);
                    os.write((msg != null ? msg : ": keep-alive\n\n").getBytes(StandardCharsets.UTF_8));
                    os.flush();
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        } catch (IOException pageClosed) {
            // The page went away; nothing to report.
        } finally {
            c.closed = true;
            clients.remove(c);
            ex.close();
        }
    }

    /** The buffered log lines as JSON, for the fallback when the live stream is down. */
    private void handleLog(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) { ex.sendResponseHeaders(405, -1); return; }
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (handshake.node.util.LogTap.Line l : handshake.node.util.LogTap.snapshot()) {
                if (!first) sb.append(",");
                first = false;
                sb.append(l.toJson());
            }
            respondJson(ex, 200, sb.append("]").toString());
        } finally {
            ex.close();
        }
    }

    /** Serves a fixed string body with the given content type. GET only
     *  -- anything else gets 405. Rejects any path other than exactly
     *  "/" on the root context, so this doesn't silently become a
     *  catch-all. */
    private void serveStatic(HttpExchange ex, String contentType, String body) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            if (ex.getHttpContext().getPath().equals("/") && !ex.getRequestURI().getPath().equals("/")) {
                ex.sendResponseHeaders(404, -1);
                return;
            }

            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", contentType);
            ex.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(bytes);
            }
        } finally {
            ex.close();
        }
    }

    private void handleStatus(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            respondJson(ex, 200, buildStatusJson());
        } finally {
            ex.close();
        }
    }

    /** The /api/status document; also what the live stream pushes. */
    private String buildStatusJson() {
        if (shutdownPhase != null && lastStatusJson != null) return lastStatusJson;
        long uptimeSeconds = (System.currentTimeMillis() - startTimeMillis) / 1000;
        int blockHeight = db.getBlockTip();
        double dbSizeGB = db.getDiskSizeBytes() / 1e9;

        // Best-known network height comes from the highest "starting
        // height" any connected peer has announced (bestKnownPeerHeight,
        // tracked in ChainSync as peers connect) -- this is the
        // standard way to gauge "how far behind the real chain am I"
        // since there's no single authoritative source for it, only
        // what peers claim. chainSync can be null very early during
        // startup before it's wired up via setChainSync(), and
        // bestKnownPeerHeight can legitimately still be 0 if no peer
        // has connected yet -- both cases report syncPercent as null
        // rather than a misleading 0% or a divide-by-zero.
        int networkHeight = (chainSync != null) ? chainSync.getBestKnownPeerHeight() : 0;
        String syncPercentField;
        if (networkHeight > 0) {
            // Capped at 100 -- our own tip can transiently exceed the
            // currently-best-connected peer's height right after that
            // peer disconnects and a shorter-tipped one is all that's
            // left, which shouldn't ever display as "101% synced".
            // Rounded DOWN, and never 100 while any block is missing: at height 352,000 even 3 blocks behind is
            // 99.9991%, which "%.1f" would otherwise print as 100.0.
            double raw = (blockHeight * 100.0) / networkHeight;
            double syncPercent = blockHeight >= networkHeight ? 100.0 : Math.min(99.9, Math.floor(raw * 10) / 10.0);
            syncPercentField = String.format(java.util.Locale.ROOT, "%.1f", syncPercent);
        } else {
            syncPercentField = "null";
        }

        // FIX (audit): halted-due-to-tree-mismatch status existed
        // internally in ChainSync (set/cleared/checked there) but
        // its public accessor was never called anywhere -- meaning
        // if the node ever actually halted on a data-integrity
        // problem, that was visible only in console/log output,
        // never in this status endpoint. Same null-safety pattern
        // as networkHeight above: chainSync can be null very early
        // during startup.
        UrkelTreeMismatchException halt = (chainSync != null) ? chainSync.haltedDueToTreeMismatch() : null;
        String haltedField = (halt != null)
                ? "{\"height\":" + halt.height
                + ",\"claimedRoot\":\"" + jsonEscape(toHex(halt.claimedRoot))
                + "\",\"computedRoot\":\"" + jsonEscape(toHex(halt.computedRoot)) + "\"}"
                : "null";

        handshake.node.util.SystemMetrics.Snapshot m = metrics.snapshot();
        String sysField = "{"
                + "\"processCpu\":" + pct(m.processCpu()) + ","
                + "\"systemCpu\":" + pct(m.systemCpu()) + ","
                + "\"heapUsed\":" + m.heapUsed() + ",\"heapMax\":" + m.heapMax() + ","
                + "\"physTotal\":" + m.physTotal() + ",\"physFree\":" + m.physFree() + ","
                + "\"diskUsable\":" + m.diskUsable() + ",\"diskTotal\":" + m.diskTotal() + ","
                + "\"diskLevel\":\"" + m.diskLevel() + "\"}";

        String storageField;
        try {
            storageField = storage.toJson(m.diskUsable(), m.diskTotal());
        } catch (RuntimeException e) {
            storageField = "null";
        }

        String json = "{"
                + "\"system\":" + sysField + ","
                + "\"storage\":" + storageField + ","
                + "\"version\":\"" + jsonEscape(NodeConfig.VERSION) + "\","
                + "\"uptime\":\"" + jsonEscape(formatUptime(uptimeSeconds)) + "\","
                + "\"blockHeight\":" + blockHeight + ","
                + "\"networkHeight\":" + networkHeight + ","
                + "\"syncPercent\":" + syncPercentField + ","
                + "\"dbSizeGB\":" + String.format(java.util.Locale.ROOT, "%.2f", dbSizeGB) + ","
                + "\"halted\":" + haltedField
                + "}";
        return json;
    }

    /** CPU load 0..1 as a percentage with one decimal, or null when the JDK reports it unknown. */
    private static String pct(double load) {
        return load < 0 ? "null" : String.format(java.util.Locale.ROOT, "%.1f", load * 100.0);
    }

    /** Formats a duration as "Xd Xh Xm Xs", omitting leading zero units
     *  (e.g. "3m 12s" rather than "0d 0h 3m 12s") so short uptimes right
     *  after startup don't look cluttered. */
    private static String formatUptime(long totalSeconds) {
        long days = totalSeconds / 86400;
        long hours = (totalSeconds % 86400) / 3600;
        long minutes = (totalSeconds % 3600) / 60;
        long seconds = totalSeconds % 60;

        StringBuilder sb = new StringBuilder();
        if (days > 0) sb.append(days).append("d ");
        if (days > 0 || hours > 0) sb.append(hours).append("h ");
        if (days > 0 || hours > 0 || minutes > 0) sb.append(minutes).append("m ");
        sb.append(seconds).append("s");
        return sb.toString();
    }

    private static String toHex(byte[] b) {
        if (b == null) return "";
        return HexUtil.encode(b);
    }

    private void handlePeers(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            if (chainSync == null) {
                respondJson(ex, 200, "[]");
                return;
            }
            respondJson(ex, 200, chainSync.getPeerInfoJson());
        } finally {
            ex.close();
        }
    }

    /** Every peer in the unified PeerTable with its live state and score.
     *  state: banned | connected | blacklisted | backoff | idle. */
    private void handlePeerTable(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            respondJson(ex, 200, buildPeerTableJson(false));
        } finally {
            ex.close();
        }
    }

    /** pushMode (live stream): leaves out never-contacted gossip addresses (they are only counted) and
     *  reports backoff as an absolute time, so the document only changes when something really changes. */
    private String buildPeerTableJson(boolean pushMode) {
        if (shutdownPhase != null) return pushMode && lastPeersPushJson != null ? lastPeersPushJson : (pushMode ? "{\"gossipOnly\":0,\"peers\":[]}" : "[]");
        java.util.Map<String, String> dirs = chainSync != null
                ? chainSync.getConnectionDirections() : java.util.Map.of();
        java.util.Map<String, String> transports = chainSync != null
                ? chainSync.getConnectionTransports() : java.util.Map.of();
        long now = System.currentTimeMillis();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        int gossipOnly = 0;
        for (PeerTable.Peer r : PeerTable.get().listAllPeers()) {
            String dir = dirs.get(r.ip);
            String state;
            if (r.banned) state = "banned";
            else if (dir != null) state = "connected";
            else if (r.isBlacklisted()) state = "blacklisted";
            else if (r.isBackedOff()) state = "backoff";
            else if (!r.hasBrontideKey()) state = "plain";
            else state = "idle";
            if (pushMode) {
                boolean verified = state.equals("connected") || r.successCount > 0 || r.isSeed;
                if (!verified && !state.equals("backoff") && !state.equals("banned") && !state.equals("blacklisted")) {
                    gossipOnly++;
                    continue;
                }
            }
            if (!first) sb.append(",");
            first = false;
            sb.append("{")
                    .append("\"ip\":\"").append(jsonEscape(r.ip)).append("\",")
                    .append("\"port\":").append(r.port).append(",")
                    .append("\"label\":\"").append(jsonEscape(r.label == null ? "" : r.label)).append("\",")
                    .append("\"source\":\"").append(jsonEscape(r.source == null ? "" : r.source)).append("\",")
                    .append("\"seed\":").append(r.isSeed).append(",")
                    .append("\"hasKey\":").append(r.hasBrontideKey()).append(",")
                    .append("\"score\":").append(r.score).append(",")
                    .append("\"state\":\"").append(state).append("\",")
                    .append("\"direction\":\"").append(dir == null ? "" : dir).append("\",")
                    .append("\"transport\":\"").append(transports.getOrDefault(r.ip, "")).append("\",")
                    .append(pushMode ? "\"backoffUntil\":" : "\"backoffMs\":")
                    .append(pushMode ? Math.max(0L, r.backoffUntil) : Math.max(0L, r.backoffUntil - now)).append(",")
                    .append("\"banReason\":\"").append(jsonEscape(r.banReason == null ? "" : r.banReason)).append("\",")
                    .append("\"banTime\":").append(r.banTime).append(",")
                    .append("\"successes\":").append(r.successCount).append(",")
                    .append("\"failures\":").append(r.failureCount).append(",")
                    .append("\"validData\":").append(r.validDataCount).append(",")
                    .append("\"invalidData\":").append(r.invalidDataCount).append(",")
                    .append("\"lastSuccess\":").append(r.lastSuccessTime).append(",")
                    .append("\"lastFailure\":").append(r.lastFailureTime).append(",")
                    .append("\"failure\":\"").append(jsonEscape(r.lastFailureReason == null ? "" : r.lastFailureReason)).append("\",")
                    .append("\"failureKind\":\"").append(jsonEscape(PeerTable.failureKind(r.lastFailureReason))).append("\",")
                    .append("\"agent\":\"").append(jsonEscape(r.lastAgent == null ? "" : r.lastAgent)).append("\",")
                    .append("\"height\":").append(r.lastHeight).append(",")
                    .append("\"latencyMs\":").append(Math.round(r.avgLatencyMs)).append(",")
                    .append("\"penalties\":[");
            boolean fp = true;
            for (String pen : PeerTable.get().recentPenalties(r)) {
                if (!fp) sb.append(",");
                fp = false;
                sb.append("\"").append(jsonEscape(pen)).append("\"");
            }
            sb.append("]}");
        }
        sb.append("]");
        if (pushMode) return "{\"gossipOnly\":" + gossipOnly + ",\"peers\":" + sb + "}";
        return sb.toString();
    }

    private void handleMempool(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            respondJson(ex, 200, buildMempoolJson());
        } finally {
            ex.close();
        }
    }

    private String buildMempoolJson() {
        if (mempool == null) return "{\"count\":0,\"bytes\":0,\"maxBytes\":0,\"minRelayFeeRate\":0}";
        return "{"
                + "\"count\":" + mempool.getAll().size() + ","
                + "\"bytes\":" + mempool.getTotalBytes() + ","
                + "\"maxBytes\":" + mempool.getMaxSize() + ","
                + "\"minRelayFeeRate\":" + mempool.getMinRelayFee()
                + "}";
    }

    private void handleBans(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (PeerTable.Peer r : PeerTable.get().listBannedPeers()) {
                if (!first) sb.append(",");
                sb.append("{")
                        .append("\"ip\":\"").append(jsonEscape(r.ip)).append("\",")
                        .append("\"reason\":\"").append(jsonEscape(r.banReason != null ? r.banReason : "")).append("\",")
                        .append("\"bannedAt\":").append(r.banTime)
                        .append("}");
                first = false;
            }
            sb.append("]");
            respondJson(ex, 200, sb.toString());
        } finally {
            ex.close();
        }
    }

    private void handleUnban(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("POST")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            if (!originMatchesSelf(ex)) {
                respondJson(ex, 403, "{\"error\":\"Origin mismatch\"}");
                return;
            }
            String body = readBody(ex);
            LinkedHashMap<String, String> fields = parseFlatJsonObject(body);
            String ip = fields.get("ip");
            if (ip == null || ip.isBlank()) {
                respondJson(ex, 400, "{\"error\":\"Missing ip\"}");
                return;
            }
            PeerTable.get().unbanPeer(ip);
            respondJson(ex, 200, "{\"ok\":true}");
        } finally {
            ex.close();
        }
    }

    private void handleClearBans(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("POST")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            if (!originMatchesSelf(ex)) {
                respondJson(ex, 403, "{\"error\":\"Origin mismatch\"}");
                return;
            }
            PeerTable.get().clearAllBans();
            respondJson(ex, 200, "{\"ok\":true}");
        } finally {
            ex.close();
        }
    }

    /** Triggers the exact same graceful shutdown path as RpcServer's own
     *  "stop" RPC method: System.exit(0) from within the running process
     *  correctly runs the registered shutdown hook (sync.stop(),
     *  p2p.stop(), db.commit(), db.close(), etc.), unlike an external
     *  forceful kill, which bypasses it entirely. A short delay lets
     *  this response actually reach the browser before the process
     *  exits. Protected the same way config changes are -- Origin check
     *  against local-CSRF -- since this is at least as sensitive an
     *  action as changing config, arguably more so. */
    private void handleStop(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("POST")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            if (!originMatchesSelf(ex)) {
                respondJson(ex, 403, "{\"error\":\"Origin mismatch\"}");
                return;
            }
            respondJson(ex, 200, "{\"ok\":true,\"message\":\"Node stopping...\"}");
            new Thread(() -> {
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                System.exit(0);
            }).start();
        } finally {
            ex.close();
        }
    }

    /**
     * Proxies a JSON-RPC call to the real RPC server (a different port,
     * so a direct browser fetch() would be blocked by the same-origin
     * policy) -- rather than adding CORS headers to RpcServer itself,
     * which could have unintended effects for other, future RPC clients
     * this project doesn't control. The browser only ever talks to this
     * server's own origin; this makes the actual internal call and
     * relays the response back verbatim.
     *
     * Includes the Basic-auth API key on the outgoing request: now that
     * Main.java always generates a real key on first run,
     * config.hasApiKey() is always true, meaning RpcServer's existing,
     * unmodified auth check genuinely requires it for every request --
     * including from this proxy itself, since RpcServer doesn't
     * special-case loopback callers at all here.
     *
     * Origin-checked like every other state-changing endpoint on this
     * page: several real RPC methods reachable through this (stop,
     * setban, sendrawtransaction, disconnectnode) are genuinely
     * sensitive, and this proxy can't distinguish read-only RPC calls
     * from those ones without a method-by-method whitelist, so the
     * simpler and safer choice is to protect the whole endpoint
     * uniformly.
     */
    private void handleRpcProxy(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("POST")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            if (!originMatchesSelf(ex)) {
                respondJson(ex, 403, "{\"error\":\"Origin mismatch\"}");
                return;
            }

            String body = readBody(ex);
            String auth = "x:" + config.getApiKey();
            String authHeader = "Basic " + Base64.getEncoder().encodeToString(
                    auth.getBytes(StandardCharsets.UTF_8));

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            HttpRequest rpcRequest = HttpRequest.newBuilder(
                            URI.create("http://" + config.getRpcHost() + ":" + config.getRpcPort() + "/"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", authHeader)
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> rpcResponse;
            try {
                rpcResponse = client.send(rpcRequest, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                respondJson(ex, 502, "{\"error\":\"Could not reach RPC server: " + jsonEscape(e.getMessage()) + "\"}");
                return;
            }

            respondJson(ex, rpcResponse.statusCode(), rpcResponse.body());
        } finally {
            ex.close();
        }
    }

    private void handleApiKey(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            String json = "{\"apiKey\":\"" + jsonEscape(config.getApiKey()) + "\"}";
            respondJson(ex, 200, json);
        } finally {
            ex.close();
        }
    }

    private void handleConfig(HttpExchange ex) throws IOException {
        try {
            if (ex.getRequestMethod().equals("GET")) {
                StringBuilder sb = new StringBuilder("{");
                sb.append("\"rpc.host\":\"").append(jsonEscape(config.getRpcHost())).append("\"");
                sb.append(",\"miner.address\":\"").append(jsonEscape(config.getMinerAddress())).append("\"");
                sb.append(",\"socket.public\":").append(config.isSocketPublic());
                sb.append("}");
                respondJson(ex, 200, sb.toString());
                return;
            }

            if (ex.getRequestMethod().equals("POST")) {
                if (!originMatchesSelf(ex)) {
                    respondJson(ex, 403, "{\"error\":\"Origin mismatch\"}");
                    return;
                }

                String body = readBody(ex);
                LinkedHashMap<String, String> fields = parseFlatJsonObject(body);
                boolean restartRequired = false;

                for (var entry : fields.entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();
                    if (!EDITABLE_KEYS.contains(key)) {
                        respondJson(ex, 400, "{\"error\":\"Unknown or non-editable key: " + jsonEscape(key) + "\"}");
                        return;
                    }
                    String validationError = validate(key, value);
                    if (validationError != null) {
                        respondJson(ex, 400, "{\"error\":\"" + jsonEscape(validationError) + "\"}");
                        return;
                    }
                    // The form always sends every field, so only a value that actually differs needs a restart.
                    if (REQUIRES_RESTART.contains(key) && !value.equals(config.getRpcHost())) restartRequired = true;
                }

                // Only write once every field has validated successfully
                // -- a partial write on the first bad field would leave
                // config in a mixed, confusing state.
                for (var entry : fields.entrySet()) {
                    config.set(entry.getKey(), entry.getKey().equals("miner.address") ? entry.getValue().trim() : entry.getValue());
                }

                respondJson(ex, 200, "{\"ok\":true,\"restartRequired\":" + restartRequired + "}");
                return;
            }

            ex.sendResponseHeaders(405, -1);
        } finally {
            ex.close();
        }
    }

    /** Validates a proposed config value; returns null if valid, or a
     *  human-readable error message if not. Deliberately rejects rather
     *  than silently coercing or storing something invalid that would
     *  only surface as a confusing failure on next restart. */
    private String validate(String key, String value) {
        // FIX: a "p2p.port"/"rpc.port" branch used to live here too, but
        // it was dead code -- validate() is only ever reached (see the
        // handleConfig() loop above) for a key that already passed
        // EDITABLE_KEYS.contains(key), and EDITABLE_KEYS has contained
        // only "rpc.host" since both ports were deliberately made
        // non-editable (see EDITABLE_KEYS's own comment for why).
        // Removed as part of the project's dead-code cleanup pass.
        return switch (key) {
            case "rpc.host" -> value.isBlank() ? "Host cannot be empty" : null;
            case "socket.public" -> (value.equals("true") || value.equals("false")) ? null : "socket.public must be true or false";
            case "miner.address" -> {
                String v = value.trim();
                if (v.isEmpty()) yield null;                       // empty = mining disabled
                try { MiningService.decodeAddress(v); yield null; }
                catch (RpcServer.RpcException e) { yield "Invalid mining reward address: " + e.getMessage(); }
            }
            default -> "Unknown key";
        };
    }

    /** True only if this request's Origin header (browsers always send
     *  one on cross-origin and same-origin POSTs alike) matches this
     *  server's own loopback origin exactly. A request with no Origin
     *  header at all (e.g. a deliberate local curl/script call, not a
     *  browser) is allowed through -- Origin spoofing isn't something a
     *  non-browser caller on the same trusted machine needs to be
     *  protected against; what this blocks is a browser silently
     *  carrying a request from some OTHER page's origin. */
    private boolean originMatchesSelf(HttpExchange ex) {
        String origin = ex.getRequestHeaders().getFirst("Origin");
        if (origin == null) return true;
        // Reached through an SSH tunnel the browser's port is often not the node's own (for example
        // http://localhost:8080 forwarded to 12080), so the port may not be compared with our own. A page is
        // same-origin when its Origin names a loopback host and is exactly the Host the request was sent to;
        // a page on another site can never satisfy both.
        try {
            java.net.URI u = java.net.URI.create(origin);
            String scheme = u.getScheme(), host = u.getHost();
            if (!"http".equals(scheme) || host == null) return false;
            boolean loopback = host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]");
            if (!loopback) return false;
            String reqHost = ex.getRequestHeaders().getFirst("Host");
            String originAuthority = u.getPort() >= 0 ? host + ":" + u.getPort() : host;
            return reqHost != null && reqHost.equalsIgnoreCase(originAuthority);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            in.transferTo(out);
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private void respondJson(HttpExchange ex, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Parses a flat {"key":"value" or number or bool, ...} JSON object
     *  -- not a general JSON parser, just enough for this specific,
     *  simple shape. Values are returned as their raw text (quotes
     *  stripped for strings) since validate() re-parses/re-checks each
     *  one against its own expected type anyway. */
    private LinkedHashMap<String, String> parseFlatJsonObject(String json) {
        LinkedHashMap<String, String> result = new LinkedHashMap<>();
        String trimmed = json.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return result;
        String inner = trimmed.substring(1, trimmed.length() - 1);

        Pattern fieldPattern = Pattern.compile(
                "\"([^\"]+)\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|true|false|-?\\d+(?:\\.\\d+)?)");
        Matcher m = fieldPattern.matcher(inner);
        while (m.find()) {
            String key = m.group(1);
            String rawValue = m.group(2);
            String value = rawValue.startsWith("\"")
                    ? rawValue.substring(1, rawValue.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\")
                    : rawValue;
            result.put(key, value);
        }
        return result;
    }

    private static String jsonEscape(String s) {
        // FIX: a real, confirmed bug -- this used to escape only '"' and
        // '\\', leaving '\n' and '\r' completely unescaped. Any admin
        // config value containing a literal newline would be emitted as
        // invalid, line-broken JSON (not a parse error client-side,
        // potentially an outright broken response). Now delegates to the
        // single shared, complete implementation.
        return JsonUtil.escape(s);
    }
}