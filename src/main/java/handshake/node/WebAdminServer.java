package handshake.node;

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
     *  now hardcoded rather than editable at all. */
    private static final Set<String> EDITABLE_KEYS = Set.of(
            "p2p.port", "rpc.port", "rpc.host"
    );

    private static final Set<String> REQUIRES_RESTART = Set.of(
            "p2p.port", "rpc.port", "rpc.host"
    );

    private final NodeConfig config;
    private final ChainDB db;
    private final long startTimeMillis = System.currentTimeMillis();
    private volatile ChainSync chainSync;
    private volatile Mempool mempool;
    private HttpServer server;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    public WebAdminServer(NodeConfig config, ChainDB db) {
        this.config = config;
        this.db = db;
    }

    public void setChainSync(ChainSync chainSync) { this.chainSync = chainSync; }
    public void setMempool(Mempool mempool) { this.mempool = mempool; }

    public void start() throws IOException {
        InetSocketAddress addr = new InetSocketAddress(
                InetAddress.getLoopbackAddress(), config.getWebAdminPort());
        server = HttpServer.create(addr, 16);
        server.createContext("/", ex -> serveStatic(ex, "text/html; charset=utf-8", WebAdminServerContent.INDEX_HTML));
        server.createContext("/style.css", ex -> serveStatic(ex, "text/css; charset=utf-8", WebAdminServerContent.STYLE_CSS));
        server.createContext("/app.js", ex -> serveStatic(ex, "application/javascript; charset=utf-8", WebAdminServerContent.APP_JS));
        server.createContext("/api/config", this::handleConfig);
        server.createContext("/api/apikey", this::handleApiKey);
        server.createContext("/api/status", this::handleStatus);
        server.createContext("/api/peers", this::handlePeers);
        server.createContext("/api/mempool", this::handleMempool);
        server.createContext("/api/bans", this::handleBans);
        server.createContext("/api/bans/unban", this::handleUnban);
        server.createContext("/api/bans/clear", this::handleClearBans);
        server.createContext("/api/stop", this::handleStop);
        server.createContext("/api/rpc", this::handleRpcProxy);
        server.setExecutor(executor);
        server.start();
    }

    public void stop() {
        if (server != null) server.stop(1);
        executor.shutdown();
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
                double syncPercent = Math.min(100.0, (blockHeight * 100.0) / networkHeight);
                syncPercentField = String.format(java.util.Locale.ROOT, "%.1f", syncPercent);
            } else {
                syncPercentField = "null";
            }

            String json = "{"
                    + "\"uptime\":\"" + jsonEscape(formatUptime(uptimeSeconds)) + "\","
                    + "\"blockHeight\":" + blockHeight + ","
                    + "\"networkHeight\":" + networkHeight + ","
                    + "\"syncPercent\":" + syncPercentField + ","
                    + "\"dbSizeGB\":" + String.format(java.util.Locale.ROOT, "%.2f", dbSizeGB)
                    + "}";
            respondJson(ex, 200, json);
        } finally {
            ex.close();
        }
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

    private void handleMempool(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            if (mempool == null) {
                respondJson(ex, 200, "{\"count\":0,\"bytes\":0,\"maxBytes\":0,\"minRelayFeeRate\":0}");
                return;
            }
            int count = mempool.getAll().size();
            String json = "{"
                    + "\"count\":" + count + ","
                    + "\"bytes\":" + mempool.getTotalBytes() + ","
                    + "\"maxBytes\":" + mempool.getMaxSize() + ","
                    + "\"minRelayFeeRate\":" + mempool.getMinRelayFee()
                    + "}";
            respondJson(ex, 200, json);
        } finally {
            ex.close();
        }
    }

    private void handleBans(HttpExchange ex) throws IOException {
        try {
            if (!ex.getRequestMethod().equals("GET")) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (PeerScorecard.PeerRecord r : PeerScorecard.get().listBannedPeers()) {
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
            PeerScorecard.get().unbanPeer(ip);
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
            PeerScorecard.get().clearAllBans();
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
                sb.append("\"p2p.port\":").append(config.getP2pPort()).append(",");
                sb.append("\"rpc.port\":").append(config.getRpcPort()).append(",");
                sb.append("\"rpc.host\":\"").append(jsonEscape(config.getRpcHost())).append("\"");
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
                    if (REQUIRES_RESTART.contains(key)) restartRequired = true;
                }

                // Only write once every field has validated successfully
                // -- a partial write on the first bad field would leave
                // config in a mixed, confusing state.
                for (var entry : fields.entrySet()) {
                    config.set(entry.getKey(), entry.getValue());
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
        return switch (key) {
            case "p2p.port", "rpc.port" -> {
                try {
                    int port = Integer.parseInt(value);
                    yield (port >= 1 && port <= 65535) ? null : "Port must be between 1 and 65535";
                } catch (NumberFormatException e) {
                    yield "Port must be a number";
                }
            }
            case "rpc.host" -> value.isBlank() ? "Host cannot be empty" : null;
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
        String expected = "http://127.0.0.1:" + config.getWebAdminPort();
        String expectedAlt = "http://localhost:" + config.getWebAdminPort();
        return origin.equals(expected) || origin.equals(expectedAlt);
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
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }
}