package handshake.validator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The real-time event/call server for wallet clients -- a WebSocket
 * transport (see WebSocketServer) carrying a Brontide-encrypted (see
 * BrontideState) JSON call/response/event protocol, replacing hsd's own
 * socket.io-based node sockets with a much simpler, custom scheme this
 * project fully controls.
 *
 * Now includes real BIP37-style Bloom filtering (see BloomFilter,
 * MurmurHash3), per client: "watch mempool"/"watch chain" with no
 * filter set behaves as before (every event, unfiltered -- useful for
 * something like a block explorer); once a client calls "set filter",
 * only transactions actually matching that filter are sent, and
 * "chain connect" events for a filtered client include the matching
 * transactions themselves plus a Merkle proof of their inclusion in
 * that block (reusing the already-tested MerkleProof), not just the
 * header. A transaction matches a filter if its txid, any output's
 * address hash, or any input's previous-transaction hash matches --
 * the same three-way check real BIP37 filters use.
 *
 * Embedded directly in the validator (not a separate broker process):
 * filtering has to run where the actual validated block/mempool
 * content lives, and running it in-process avoids adding a network hop
 * in front of that anyway.
 */
public class NodeSocketServer {

    private final NodeConfig config;
    private final ChainDB db;
    private final NodeIdentity identity;
    private final ChainSync chainSync;
    private Mempool mempool;
    private WebSocketServer wsServer;

    private final List<ClientSession> sessions = new CopyOnWriteArrayList<>();

    public NodeSocketServer(NodeConfig config, ChainDB db, NodeIdentity identity, ChainSync chainSync) {
        this.config = config;
        this.db = db;
        this.identity = identity;
        this.chainSync = chainSync;
    }

    public void setMempool(Mempool mempool) {
        this.mempool = mempool;
        mempool.addTxListener(this::onNewMempoolTx);
    }

    public void registerWithRpc(RpcServer rpc) {
        rpc.addBlockListener((height, hash, rawBlock) -> onNewBlock(height, hash, rawBlock));
    }

    public void start() throws IOException {
        wsServer = new WebSocketServer(config.getSocketPort(), this::onConnect);
        wsServer.start();
        System.out.println("[NodeSocketServer] Listening on port " + config.getSocketPort());
    }

    public void stop() {
        if (wsServer != null) wsServer.stop();
        for (ClientSession s : sessions) s.conn.close();
    }

    // ── Per-connection session ──────────────────────────────────────────────

    private static class ClientSession {
        final WebSocketConnection conn;
        final BrontideState brontide;
        boolean authenticated = false;
        boolean watchingChain = false;
        boolean watchingMempool = false;
        volatile BloomFilter filter = null;

        ClientSession(WebSocketConnection conn, BrontideState brontide) {
            this.conn = conn;
            this.brontide = brontide;
        }
    }

    private void onConnect(WebSocketConnection conn) {
        new Thread(() -> {
            try {
                BrontideState brontide = new BrontideState(identity.getPrivateKey());

                byte[] actOne = conn.receiveBinary();
                if (actOne == null || actOne.length != BrontideState.ACT_ONE_SIZE) {
                    conn.close();
                    return;
                }
                brontide.recvActOne(actOne);

                byte[] actTwo = brontide.genActTwo();
                conn.sendBinary(actTwo);

                byte[] actThree = conn.receiveBinary();
                if (actThree == null || actThree.length != BrontideState.ACT_THREE_SIZE) {
                    conn.close();
                    return;
                }
                brontide.recvActThree(actThree);

                if (!brontide.isReady()) {
                    conn.close();
                    return;
                }

                ClientSession session = new ClientSession(conn, brontide);
                sessions.add(session);
                System.out.println("[NodeSocketServer] Client connected: " + conn.remoteIp);

                messageLoop(session);
            } catch (Exception e) {
                // handshake or connection failure -- just drop it
            } finally {
                conn.close();
            }
        }, "socket-client-" + conn.remoteIp).start();
    }

    private void messageLoop(ClientSession session) {
        try {
            while (!session.conn.isClosed()) {
                byte[] encrypted = session.conn.receiveBinary();
                if (encrypted == null) break;

                byte[] plaintext;
                try {
                    plaintext = session.brontide.decryptMessage(encrypted);
                } catch (Exception e) {
                    break;
                }

                String json = new String(plaintext, StandardCharsets.UTF_8);
                handleCall(session, json);
            }
        } catch (Exception e) {
            // fall through to cleanup
        } finally {
            sessions.remove(session);
            session.conn.close();
        }
    }

    private void sendJson(ClientSession session, String json) {
        try {
            byte[] encrypted = session.brontide.encryptMessage(json.getBytes(StandardCharsets.UTF_8));
            session.conn.sendBinary(encrypted);
        } catch (Exception e) {
            session.conn.close();
        }
    }

    // ── Call dispatch ────────────────────────────────────────────────────────

    private void handleCall(ClientSession session, String json) {
        Integer id = extractId(json);
        String method = extractMethod(json);
        String params = extractParams(json);

        if (method == null) {
            sendResponse(session, id, null, "Invalid call: missing method");
            return;
        }

        if (!method.equals("auth") && !session.authenticated) {
            sendResponse(session, id, null, "Not authenticated");
            return;
        }

        try {
            switch (method) {
                case "auth" -> {
                    String key = firstStringParam(params);
                    String expected = config.getApiKey();
                    boolean ok = expected == null || expected.isBlank() || expected.equals(key);
                    if (!ok) {
                        sendResponse(session, id, null, "Invalid API key");
                        return;
                    }
                    session.authenticated = true;
                    sendResponse(session, id, "null", null);
                }
                case "watch chain" -> {
                    session.watchingChain = true;
                    sendResponse(session, id, "null", null);
                }
                case "unwatch chain" -> {
                    session.watchingChain = false;
                    sendResponse(session, id, "null", null);
                }
                case "watch mempool" -> {
                    session.watchingMempool = true;
                    sendResponse(session, id, "null", null);
                }
                case "unwatch mempool" -> {
                    session.watchingMempool = false;
                    sendResponse(session, id, "null", null);
                }
                case "set filter" -> {
                    session.filter = parseFilterParam(params);
                    sendResponse(session, id, "null", null);
                }
                case "add filter" -> {
                    if (session.filter == null) {
                        sendResponse(session, id, null, "No filter set -- call \"set filter\" first");
                        return;
                    }
                    for (byte[] elem : parseHexArrayParam(params)) {
                        session.filter.add(elem);
                    }
                    sendResponse(session, id, "null", null);
                }
                case "reset filter" -> {
                    session.filter = null;
                    sendResponse(session, id, "null", null);
                }
                case "get tip" -> {
                    int tip = db.getHeaderTip();
                    sendResponse(session, id, tip >= 0 ? chainEntryJson(tip, null) : "null", null);
                }
                case "get entry" -> {
                    String hashOrHeight = firstStringParam(params);
                    int height = resolveHeight(hashOrHeight);
                    sendResponse(session, id, height >= 0 ? chainEntryJson(height, null) : "null", null);
                }
                case "get hashes" -> {
                    List<String> args = parseArrayOfInts(params);
                    int start = args.size() > 0 ? Integer.parseInt(args.get(0)) : 0;
                    int end = args.size() > 1 ? Integer.parseInt(args.get(1)) : db.getHeaderTip();
                    sendResponse(session, id, hashesJson(start, end), null);
                }
                case "estimate fee" -> {
                    double rate = mempool != null ? medianMempoolFeeRate() : -1;
                    sendResponse(session, id, String.valueOf(rate < 0 ? -1 : rate / 1_000_000.0), null);
                }
                case "send" -> {
                    byte[] raw = firstBytesParam(params);
                    if (raw == null || mempool == null) {
                        sendResponse(session, id, null, "Invalid transaction");
                        return;
                    }
                    String txid = mempool.submit(raw);
                    sendResponse(session, id, "null", txid == null ? "Transaction rejected" : null);
                }
                default -> sendResponse(session, id, null, "Unknown method: " + method);
            }
        } catch (Exception e) {
            sendResponse(session, id, null, "Error: " + e.getMessage());
        }
    }

    private void sendResponse(ClientSession session, Integer id, String resultJson, String error) {
        String idPart = id != null ? String.valueOf(id) : "null";
        String errPart = error != null ? "\"" + jsonEscape(error) + "\"" : "null";
        String result = resultJson != null ? resultJson : "null";
        sendJson(session, "{\"id\":" + idPart + ",\"result\":" + result + ",\"error\":" + errPart + "}");
    }

    // ── Event push ───────────────────────────────────────────────────────────

    private void onNewBlock(int height, byte[] hash, byte[] rawBlock) {
        List<TxParser.ParsedTx> txs = null;
        for (ClientSession s : sessions) {
            if (!s.authenticated || !s.watchingChain) continue;
            if (s.filter == null) {
                sendJson(s, "{\"event\":\"chain connect\",\"data\":" + chainEntryJson(height, null) + "}");
                continue;
            }
            if (txs == null) txs = BlockProcessor.parseBlockTxs(rawBlock);
            sendJson(s, "{\"event\":\"chain connect\",\"data\":" + chainEntryJson(height, matchFilterInBlock(s.filter, txs)) + "}");
        }
    }

    private void onNewMempoolTx(Mempool.MempoolEntry entry) {
        for (ClientSession s : sessions) {
            if (!s.authenticated || !s.watchingMempool) continue;
            if (s.filter != null && !matches(s.filter, entry)) continue;
            String event = "{\"event\":\"tx\",\"data\":{\"hash\":\"" + entry.txid + "\",\"size\":"
                    + entry.size + ",\"fee\":" + entry.fee + "}}";
            sendJson(s, event);
        }
    }

    private boolean matches(BloomFilter filter, Mempool.MempoolEntry entry) {
        TxParser.ParsedTx tx = TxParser.parse(entry.raw);
        if (tx == null) return false;
        return matchesParsedTx(filter, tx, entry.txid);
    }

    private boolean matchesParsedTx(BloomFilter filter, TxParser.ParsedTx tx, String txid) {
        if (filter.contains(hexToBytes(txid))) return true;
        for (TxParser.Output out : tx.outputs) {
            if (out.addrHash != null && filter.contains(out.addrHash)) return true;
        }
        for (TxParser.Input in : tx.inputs) {
            if (in.prevHash != null && filter.contains(in.prevHash)) return true;
        }
        return false;
    }

    private static class FilterMatch {
        List<TxParser.ParsedTx> matchedTxs = new ArrayList<>();
        List<String> matchedTxids = new ArrayList<>();
        MerkleProof.BuiltProof proof;
    }

    private FilterMatch matchFilterInBlock(BloomFilter filter, List<TxParser.ParsedTx> txs) {
        FilterMatch result = new FilterMatch();
        List<byte[]> leaves = new ArrayList<>();
        boolean[] matchFlags = new boolean[txs.size()];

        for (int i = 0; i < txs.size(); i++) {
            TxParser.ParsedTx tx = txs.get(i);
            String txid = TxParser.computeTxid(tx.raw);
            leaves.add(hexToBytes(txid));
            if (matchesParsedTx(filter, tx, txid)) {
                matchFlags[i] = true;
                result.matchedTxs.add(tx);
                result.matchedTxids.add(txid);
            }
        }

        if (!result.matchedTxids.isEmpty()) {
            result.proof = MerkleProof.buildProof(leaves, matchFlags);
        }
        return result;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String chainEntryJson(int height, FilterMatch match) {
        byte[] header = db.getHeader(height);
        if (header == null) return "null";
        BigIntegerOrZero work = new BigIntegerOrZero(db.getChainwork(height));

        StringBuilder sb = new StringBuilder("{");
        sb.append("\"hash\":\"").append(hex(HeaderUtil.hash(header))).append("\",");
        sb.append("\"height\":").append(height).append(",");
        sb.append("\"version\":").append(HeaderUtil.version(header)).append(",");
        sb.append("\"prevBlock\":\"").append(hex(HeaderUtil.prevBlock(header))).append("\",");
        sb.append("\"merkleRoot\":\"").append(hex(HeaderUtil.merkleRoot(header))).append("\",");
        sb.append("\"time\":").append(HeaderUtil.time(header)).append(",");
        sb.append("\"bits\":").append(HeaderUtil.bits(header)).append(",");
        sb.append("\"chainwork\":\"").append(work).append("\",");

        sb.append("\"matches\":[");
        if (match != null) {
            for (int i = 0; i < match.matchedTxs.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("{\"txid\":\"").append(match.matchedTxids.get(i)).append("\",")
                        .append("\"hex\":\"").append(hex(match.matchedTxs.get(i).raw)).append("\"}");
            }
        }
        sb.append("],");

        if (match != null && match.proof != null) {
            sb.append("\"proof\":{");
            sb.append("\"totalTX\":").append(match.proof.totalTX).append(",");
            sb.append("\"hashes\":[");
            for (int i = 0; i < match.proof.hashes.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(hex(match.proof.hashes.get(i))).append("\"");
            }
            sb.append("],");
            sb.append("\"flags\":\"").append(hex(match.proof.flags)).append("\"");
            sb.append("}");
        } else {
            sb.append("\"proof\":null");
        }

        sb.append("}");
        return sb.toString();
    }

    private static class BigIntegerOrZero {
        final java.math.BigInteger value;
        BigIntegerOrZero(java.math.BigInteger v) { this.value = v; }
        public String toString() { return value != null ? value.toString(16) : "00"; }
    }

    private String hashesJson(int start, int end) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (int h = start; h <= end; h++) {
            byte[] header = db.getHeader(h);
            if (header == null) continue;
            if (!first) sb.append(",");
            sb.append("\"").append(hex(HeaderUtil.hash(header))).append("\"");
            first = false;
        }
        return sb.append("]").toString();
    }

    private int resolveHeight(String hashOrHeight) {
        if (hashOrHeight == null) return -1;
        try {
            return Integer.parseInt(hashOrHeight);
        } catch (NumberFormatException e) {
            return db.getHeightByHash(hashOrHeight);
        }
    }

    private double medianMempoolFeeRate() {
        List<Double> rates = new ArrayList<>();
        for (Mempool.MempoolEntry e : mempool.getAll()) {
            rates.add(e.fee / (e.size / 1000.0));
        }
        if (rates.isEmpty()) return -1;
        Collections.sort(rates);
        return rates.get(rates.size() / 2);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] hexToBytes(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
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

    // ── Minimal JSON envelope parsing ───────────────────────────────────────

    private Integer extractId(String json) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"id\"\\s*:\\s*(\\d+)").matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : null;
    }

    private String extractMethod(String json) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"method\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private String extractParams(String json) {
        int idx = json.indexOf("\"params\"");
        if (idx < 0) return "[]";
        int colon = json.indexOf(':', idx);
        int arrayStart = json.indexOf('[', colon);
        if (arrayStart < 0) return "[]";
        int depth = 0;
        for (int i = arrayStart; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '[') depth++;
            else if (c == ']') {
                depth--;
                if (depth == 0) return json.substring(arrayStart, i + 1);
            }
        }
        return "[]";
    }

    private String firstStringParam(String paramsArray) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"([^\"]*)\"").matcher(paramsArray);
        return m.find() ? m.group(1) : null;
    }

    private byte[] firstBytesParam(String paramsArray) {
        String s = firstStringParam(paramsArray);
        return s != null ? hexToBytes(s) : null;
    }

    private List<String> parseArrayOfInts(String paramsArray) {
        List<String> result = new ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("-?\\d+").matcher(paramsArray);
        while (m.find()) result.add(m.group());
        return result;
    }

    private BloomFilter parseFilterParam(String paramsArray) {
        java.util.regex.Matcher dataM = java.util.regex.Pattern.compile("\"data\"\\s*:\\s*\"([0-9a-fA-F]*)\"").matcher(paramsArray);
        java.util.regex.Matcher hashFuncsM = java.util.regex.Pattern.compile("\"hashFuncs\"\\s*:\\s*(\\d+)").matcher(paramsArray);
        java.util.regex.Matcher tweakM = java.util.regex.Pattern.compile("\"tweak\"\\s*:\\s*(-?\\d+)").matcher(paramsArray);
        if (!dataM.find() || !hashFuncsM.find() || !tweakM.find()) {
            throw new IllegalArgumentException("set filter requires {data, hashFuncs, tweak}");
        }
        byte[] data = hexToBytes(dataM.group(1));
        int hashFuncs = Integer.parseInt(hashFuncsM.group(1));
        int tweak = (int) Long.parseLong(tweakM.group(1));
        return new BloomFilter(data, hashFuncs, tweak);
    }

    private List<byte[]> parseHexArrayParam(String paramsArray) {
        List<byte[]> result = new ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"([0-9a-fA-F]+)\"").matcher(paramsArray);
        while (m.find()) result.add(hexToBytes(m.group(1)));
        return result;
    }
}