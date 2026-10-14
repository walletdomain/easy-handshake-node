package handshake.node.server;

import handshake.node.NodeConfig;
import handshake.node.chain.BlockProcessor;
import handshake.node.chain.ChainSync;
import handshake.node.chain.HeaderUtil;
import handshake.node.chain.Mempool;
import handshake.node.chain.TxParser;
import handshake.node.crypto.Bech32;
import handshake.node.peer.NodeIdentity;
import handshake.node.storage.ChainDB;
import handshake.node.storage.IndexStore;
import handshake.node.util.HexUtil;
import handshake.node.util.NodeClock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * hsd's node REST API (lib/node/http.js) on top of our storage: same routes, same JSON, same status codes, so any
 * client written for hsd's HTTP interface works against this node.
 *
 * Differences from hsd, all deliberate:
 *  - /tx/address and /coin/address answer at most {@link #MAX_RESULTS} entries (hsd has no limit and warns that big
 *    answers exhaust the CPU). Rather than silently truncating, a larger answer is refused with an error that names
 *    the optional extension parameters ?limit=N&after=TXID (txs) / ?limit=N&after=TXID:INDEX (coins) which page
 *    through the index in its own order. /tx/address is ordered by block position (hsd: by txid).
 *  - POST /claim is refused: this node keeps no claim pool.
 *  - POST /reset is handled by the caller (it needs the reorg machinery).
 */
final class RestApi {
    static final int MAX_RESULTS = 10_000;

    /** An HTTP answer: status plus body ("" = empty body, as hsd sends for 404). */
    record Response(int status, String body) {}

    private final ChainDB db;
    private final Mempool mempool;
    private final ChainSync sync;
    private final NodeConfig config;
    private final long startedMs = System.currentTimeMillis();

    RestApi(ChainDB db, Mempool mempool, ChainSync sync, NodeConfig config) {
        this.db = db;
        this.mempool = mempool;
        this.sync = sync;
        this.config = config;
    }

    /** True for the paths this API answers (everything but "/" on POST, which stays JSON-RPC). */
    static boolean isRestPath(String method, String path) {
        if ("GET".equals(method)) return true;
        return !(path.equals("/") || path.isEmpty());
    }

    // ── errors ───────────────────────────────────────────────────────────────

    private static final class HttpError extends Exception {
        final int status;
        HttpError(int status, String message) { super(message); this.status = status; }
    }

    private static Response error(int status, String message) {
        return new Response(status, "{\"error\":{\"type\":\"Error\",\"message\":\"" + escape(message) + "\"}}");
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') sb.append('\\').append(c);
            else if (c < 0x20) sb.append(' ');
            else sb.append(c);
        }
        return sb.toString();
    }

    private static final Response NOT_FOUND = new Response(404, "");

    // ── dispatch ─────────────────────────────────────────────────────────────

    Response handle(String method, String path, String query, String body) {
        try {
            String[] seg = path.split("/");           // "" , "tx", ...
            List<String> p = new ArrayList<>();
            for (String s : seg) if (!s.isEmpty()) p.add(s);
            java.util.Map<String, String> q = parseQuery(query);

            if (method.equals("GET")) return get(p, q);
            if (method.equals("POST")) return post(p, body);
            return NOT_FOUND;
        } catch (HttpError e) {
            return error(e.status, e.getMessage());
        } catch (RuntimeException e) {
            System.err.println("[REST] " + method + " " + path + " failed: " + e);
            return error(500, "Internal error");
        }
    }

    private Response get(List<String> p, java.util.Map<String, String> q) throws HttpError {
        int n = p.size();
        if (n == 0) return new Response(200, info());
        String a = p.get(0);

        if (a.equals("coin") && n == 3 && p.get(1).equals("address")) return coinsByAddresses(List.of(p.get(2)), q);
        if (a.equals("coin") && n == 3) return coin(p.get(1), p.get(2));
        if (a.equals("tx") && n == 3 && p.get(1).equals("address")) return txsByAddresses(List.of(p.get(2)), q);
        if (a.equals("tx") && n == 2) return txByHash(p.get(1));
        if (a.equals("block") && n == 2) return block(p.get(1));
        if (a.equals("header") && n == 2) return header(p.get(1));
        if (a.equals("mempool") && n == 1) return mempoolList();
        if (a.equals("mempool") && n == 2 && p.get(1).equals("invalid")) return mempoolInvalid();
        if (a.equals("mempool") && n == 3 && p.get(1).equals("invalid")) return mempoolInvalidHash(p.get(2));
        if (a.equals("fee") && n == 1) return fee(q);
        return NOT_FOUND;
    }

    private Response post(List<String> p, String body) throws HttpError {
        int n = p.size();
        String a = n > 0 ? p.get(0) : "";
        if (a.equals("broadcast") && n == 1) return broadcast(body);
        if (a.equals("claim") && n == 1) throw new HttpError(400, "This node keeps no claim pool; claims are not accepted over REST.");
        if (a.equals("coin") && n == 2 && p.get(1).equals("address")) return coinsByAddresses(addresses(body), java.util.Map.of());
        if (a.equals("tx") && n == 2 && p.get(1).equals("address")) return txsByAddresses(addresses(body), java.util.Map.of());
        return NOT_FOUND;
    }

    // ── request parsing ──────────────────────────────────────────────────────

    private static java.util.Map<String, String> parseQuery(String query) {
        java.util.Map<String, String> m = new java.util.HashMap<>();
        if (query == null || query.isEmpty()) return m;
        for (String kv : query.split("&")) {
            int i = kv.indexOf('=');
            String k = i < 0 ? kv : kv.substring(0, i);
            String v = i < 0 ? "" : kv.substring(i + 1);
            try {
                m.put(java.net.URLDecoder.decode(k, "UTF-8"), java.net.URLDecoder.decode(v, "UTF-8"));
            } catch (Exception ignored) { }
        }
        return m;
    }

    private static final Pattern TX_FIELD = Pattern.compile("\"tx\"\\s*:\\s*\"([0-9a-fA-F]*)\"");
    private static final Pattern ADDR_ARRAY = Pattern.compile("\"addresses\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL);
    private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"");

    private static List<String> addresses(String body) throws HttpError {
        Matcher m = ADDR_ARRAY.matcher(body == null ? "" : body);
        if (!m.find()) throw new HttpError(400, "Addresses is required.");
        List<String> out = new ArrayList<>();
        Matcher q = QUOTED.matcher(m.group(1));
        while (q.find()) out.add(q.group(1));
        return out;
    }

    private static byte[] hash32(String s, String what) throws HttpError {
        if (s == null || s.length() != 64) throw new HttpError(400, what + " is required.");
        try { return HexUtil.decode(s); }
        catch (RuntimeException e) { throw new HttpError(400, what + " is required."); }
    }

    private record Addr(int version, byte[] hash) {}

    private Addr address(String s, ChainJson cj) throws HttpError {
        try {
            Object[] d = Bech32.decode(s);
            if (!cj.hrp().equals(d[0])) throw new HttpError(400, "Address is for a different network.");
            return new Addr((Integer) d[1], (byte[]) d[2]);
        } catch (HttpError e) {
            throw e;
        } catch (RuntimeException e) {
            throw new HttpError(400, "Invalid address.");
        }
    }

    // ── GET / ────────────────────────────────────────────────────────────────

    private String info() {
        int height = db.getBlockTip();
        byte[] h = height >= 0 ? db.getHeader(height) : null;
        long now = NodeClock.nowSec();
        double progress = 0;
        byte[] g = db.getHeader(0);
        if (h != null && g != null) {
            long start = HeaderUtil.time(g);
            double end = now - start - 40 * 60;
            progress = end <= 0 ? 1 : Math.min(1.0, (HeaderUtil.time(h) - start) / end);
        }
        int treeInterval = BlockProcessor.params.treeInterval;
        int prev = height - 1;
        int treeRootHeight = height <= 0 ? 0 : prev - (prev % treeInterval) + 1;
        String key = "";
        try {
            NodeIdentity id = NodeIdentity.get();
            if (id != null) key = id.getBrontideAddress("x", 0).split("@")[0];
        } catch (RuntimeException ignored) { }
        int peers = sync != null ? sync.getConnectedPeerCount() : 0;
        int mp = mempool != null ? mempool.size() : 0;
        long mpBytes = mempool != null ? mempool.getTotalBytes() : 0;

        return "{\"version\":\"" + NodeConfig.VERSION + "\",\"network\":\"" + BlockProcessor.params.type + "\","
                + "\"chain\":{\"height\":" + height
                + ",\"tip\":" + (h == null ? "null" : "\"" + ChainJson.hex(HeaderUtil.hash(h)) + "\"")
                + ",\"treeRoot\":" + (h == null ? "null" : "\"" + ChainJson.hex(HeaderUtil.treeRoot(h)) + "\"")
                + ",\"treeRootHeight\":" + treeRootHeight
                + ",\"progress\":" + progress
                + ",\"indexers\":{\"indexTX\":" + (db.index() != null) + ",\"indexAddress\":" + db.addressIndexEnabled() + "}"
                + ",\"options\":{\"spv\":false,\"prune\":false}"
                + ",\"treeCompaction\":{\"compacted\":false,\"compactOnInit\":false,\"compactInterval\":null,"
                + "\"lastCompaction\":null,\"nextCompaction\":null}"
                + ",\"state\":{\"tx\":0,\"coin\":" + db.getUtxoCount() + ",\"value\":0,\"burned\":0}}"
                + ",\"pool\":{\"host\":\"" + escape(config.getRpcHost()) + "\",\"port\":" + config.getP2pPort()
                + ",\"brontidePort\":" + config.getP2pPort()
                + ",\"identitykey\":\"" + key + "\",\"agent\":\"/easy-handshake-node:" + NodeConfig.VERSION + "/\""
                + ",\"services\":\"1\",\"outbound\":" + peers + ",\"inbound\":0"
                + ",\"public\":{\"listen\":false,\"host\":null,\"port\":null,\"brontidePort\":null}}"
                + ",\"mempool\":{\"tx\":" + mp + ",\"size\":" + mpBytes + ",\"claims\":0,\"airdrops\":0,\"orphans\":0}"
                + ",\"time\":{\"uptime\":" + (System.currentTimeMillis() - startedMs) / 1000
                + ",\"system\":" + System.currentTimeMillis() / 1000 + ",\"adjusted\":" + now
                + ",\"offset\":" + NodeClock.offsetSec() + "}"
                + ",\"memory\":{\"total\":" + (Runtime.getRuntime().totalMemory() >> 20)
                + ",\"jsHeap\":0,\"jsHeapTotal\":0,\"nativeHeap\":0,\"external\":0}}";
    }

    // ── blocks / headers ─────────────────────────────────────────────────────

    /** hsd's block parameter: a 64-hex hash or a height. Returns the height, or -1 when it names nothing. */
    private int blockHeight(String s) throws HttpError {
        if (s.length() == 64) {
            byte[] h = hash32(s, "Hash");
            int ht = db.getHeightByHash(h);
            return ht <= db.getBlockTip() ? ht : -1;
        }
        try {
            long v = Long.parseLong(s);
            if (v < 0 || v > db.getBlockTip()) return -1;
            return (int) v;
        } catch (NumberFormatException e) {
            throw new HttpError(400, "Hash or height required.");
        }
    }

    private Response block(String s) throws HttpError {
        int height = blockHeight(s);
        if (height < 0) return NOT_FOUND;
        byte[] raw = db.getBlock(height), h = db.getHeader(height);
        if (raw == null || h == null) return NOT_FOUND;
        return new Response(200, new ChainJson(db, mempool).block(h, height, db.getBlockTip(), raw));
    }

    private Response header(String s) throws HttpError {
        int height = blockHeight(s);
        if (height < 0) return NOT_FOUND;
        byte[] h = db.getHeader(height);
        if (h == null) return NOT_FOUND;
        return new Response(200, new ChainJson(db, mempool).header(h, height));
    }

    // ── transactions ─────────────────────────────────────────────────────────

    private Response txByHash(String s) throws HttpError {
        byte[] id = hash32(s, "Hash");
        ChainJson cj = new ChainJson(db, mempool);
        int tip = db.getBlockTip();
        IndexStore.TxLoc loc = cj.locate(id);
        if (loc != null && loc.height() <= tip) {
            TxParser.ParsedTx t = cj.txAt(loc, id);
            if (t != null) return new Response(200, cj.confirmedTx(t, loc.height(), loc.pos(), tip));
        }
        if (mempool != null) {
            byte[] raw = mempool.getRaw(ChainJson.hex(id));
            Mempool.MempoolEntry e = mempool.getEntry(ChainJson.hex(id));
            if (raw != null) {
                TxParser.ParsedTx t = TxParser.parse(raw);
                if (t != null) {
                    long mtime = e != null ? e.addedAt / 1000 : NodeClock.nowSec();
                    return new Response(200, cj.tx(t, ChainJson.Meta.mempool(mtime), -1, mtime, tip));
                }
            }
        }
        if (db.index() == null) throw new HttpError(400, "Transaction index is not enabled.");
        return NOT_FOUND;
    }

    private Response txsByAddresses(List<String> addrs, java.util.Map<String, String> q) throws HttpError {
        if (db.index() == null || !db.addressIndexEnabled()) throw new HttpError(400, "Address index is not enabled.");
        ChainJson cj = new ChainJson(db, mempool);
        int tip = db.getBlockTip();
        int limit = MAX_RESULTS;
        boolean explicit = false;
        if (q.containsKey("limit")) {
            try { limit = Math.min(MAX_RESULTS, Math.max(1, Integer.parseInt(q.get("limit")))); explicit = true; }
            catch (NumberFormatException e) { throw new HttpError(400, "Invalid limit."); }
        }
        IndexStore.AddrTx after = null;
        if (q.containsKey("after")) {
            byte[] aid = hash32(q.get("after"), "after");
            IndexStore.TxLoc l = cj.locate(aid);
            if (l == null) throw new HttpError(400, "Unknown 'after' transaction.");
            after = new IndexStore.AddrTx(l.height(), l.pos(), aid);
        }
        boolean reverse = "true".equals(q.get("reverse")) || "1".equals(q.get("reverse"));

        StringBuilder sb = new StringBuilder("[");
        int count = 0;
        Set<String> seen = new HashSet<>();
        List<Addr> parsed = new ArrayList<>();
        for (String a : addrs) parsed.add(address(a, cj));

        for (Addr ad : parsed) {
            int remaining = limit - count;
            if (remaining <= 0) break;
            List<IndexStore.AddrTx> page = pageTxs(ad, remaining + (explicit ? 0 : 1), after, reverse);
            if (!explicit && page.size() > remaining) throw tooMany("/tx/address");
            for (IndexStore.AddrTx at : page) {
                String idHex = ChainJson.hex(at.txid());
                if (!seen.add(idHex)) continue;
                TxParser.ParsedTx t = cj.txAt(new IndexStore.TxLoc(at.height(), at.pos()), at.txid());
                if (t == null) continue;
                if (count++ > 0) sb.append(',');
                sb.append(cj.confirmedTx(t, at.height(), at.pos(), tip));
            }
        }

        // Mempool transactions touching these addresses follow the confirmed ones, as in hsd.
        if (mempool != null) {
            for (Mempool.MempoolEntry e : mempool.getAll()) {
                if (!seen.add(e.txid)) continue;
                TxParser.ParsedTx t = TxParser.parse(e.raw);
                if (t == null || !touches(t, parsed, cj)) continue;
                long mtime = e.addedAt / 1000;
                if (count++ > 0) sb.append(',');
                sb.append(cj.tx(t, ChainJson.Meta.mempool(mtime), -1, mtime, tip));
            }
        }
        return new Response(200, sb.append(']').toString());
    }

    private List<IndexStore.AddrTx> pageTxs(Addr a, int limit, IndexStore.AddrTx after, boolean reverse) {
        List<IndexStore.AddrTx> out = new ArrayList<>();
        IndexStore.AddrTx cursor = after;
        // IndexStore pages are capped at MAX_PAGE; keep asking until we have what was wanted.
        while (out.size() < limit) {
            List<IndexStore.AddrTx> page = db.index().addressTxs(a.version(), a.hash(),
                    Math.min(IndexStore.MAX_PAGE, limit - out.size()), cursor, reverse);
            if (page.isEmpty()) break;
            out.addAll(page);
            cursor = page.get(page.size() - 1);
            if (page.size() < Math.min(IndexStore.MAX_PAGE, limit)) break;
        }
        return out;
    }

    /** Does the transaction pay to, or (through a resolvable input) spend from, one of the addresses? */
    private boolean touches(TxParser.ParsedTx t, List<Addr> addrs, ChainJson cj) {
        for (TxParser.Output o : t.outputs) if (matches(o, addrs)) return true;
        for (TxParser.Input in : t.inputs) {
            if (in.isCoinbase()) continue;
            ChainJson.Coin c = cj.resolve(in.prevHash, in.prevIndex);
            if (c != null && matches(c.out(), addrs)) return true;
        }
        return false;
    }

    private static boolean matches(TxParser.Output o, List<Addr> addrs) {
        for (Addr a : addrs) if (a.version() == o.addrVersion && Arrays.equals(a.hash(), o.addrHash)) return true;
        return false;
    }

    private static HttpError tooMany(String route) {
        return new HttpError(400, "More than " + MAX_RESULTS + " results for " + route
                + "; page through them with ?limit=N&after=<last txid" + (route.startsWith("/coin") ? ":index" : "") + ">.");
    }

    // ── coins ────────────────────────────────────────────────────────────────

    private Response coin(String hash, String idx) throws HttpError {
        byte[] id = hash32(hash, "Hash");
        int index;
        try { index = Integer.parseInt(idx); } catch (NumberFormatException e) { throw new HttpError(400, "Index is required."); }
        if (index < 0) throw new HttpError(400, "Index is required.");
        ChainJson cj = new ChainJson(db, mempool);
        String idHex = ChainJson.hex(id);

        if (mempool != null) {
            byte[] raw = mempool.getRaw(idHex);
            if (raw != null) {
                TxParser.ParsedTx t = TxParser.parse(raw);
                if (t != null && index < t.outputs.size() && !spentInMempool(id, index)) {
                    return new Response(200, cj.mempoolCoin(t, index));
                }
                return NOT_FOUND;
            }
            if (spentInMempool(id, index)) return NOT_FOUND;
        }
        ChainDB.UtxoEntry e = db.getUtxo(idHex, index);
        if (e == null) return NOT_FOUND;
        return new Response(200, cj.utxoCoin(id, index, e));
    }

    private boolean spentInMempool(byte[] txid, int index) {
        if (mempool == null) return false;
        for (Mempool.MempoolEntry e : mempool.getAll()) {
            TxParser.ParsedTx t = TxParser.parse(e.raw);
            if (t == null) continue;
            for (TxParser.Input in : t.inputs)
                if (in.prevIndex == index && Arrays.equals(in.prevHash, txid)) return true;
        }
        return false;
    }

    private Response coinsByAddresses(List<String> addrs, java.util.Map<String, String> q) throws HttpError {
        if (db.index() == null || !db.addressIndexEnabled()) throw new HttpError(400, "Address index is not enabled.");
        ChainJson cj = new ChainJson(db, mempool);
        int limit = MAX_RESULTS;
        boolean explicit = false;
        if (q.containsKey("limit")) {
            try { limit = Math.min(MAX_RESULTS, Math.max(1, Integer.parseInt(q.get("limit")))); explicit = true; }
            catch (NumberFormatException e) { throw new HttpError(400, "Invalid limit."); }
        }
        IndexStore.Outpoint after = null;
        if (q.containsKey("after")) {
            String[] parts = q.get("after").split(":");
            if (parts.length != 2) throw new HttpError(400, "'after' must be TXID:INDEX.");
            try { after = new IndexStore.Outpoint(hash32(parts[0], "after"), Integer.parseInt(parts[1])); }
            catch (NumberFormatException e) { throw new HttpError(400, "'after' must be TXID:INDEX."); }
        }

        List<Addr> parsed = new ArrayList<>();
        for (String a : addrs) parsed.add(address(a, cj));

        // Mempool: which outpoints are spent there, and which of its outputs pay these addresses.
        Set<String> spent = new HashSet<>();
        List<TxParser.ParsedTx> mpTxs = new ArrayList<>();
        if (mempool != null) {
            for (Mempool.MempoolEntry e : mempool.getAll()) {
                TxParser.ParsedTx t = TxParser.parse(e.raw);
                if (t == null) continue;
                mpTxs.add(t);
                for (TxParser.Input in : t.inputs)
                    if (!in.isCoinbase()) spent.add(ChainJson.hex(in.prevHash) + ":" + in.prevIndex);
            }
        }

        StringBuilder sb = new StringBuilder("[");
        int count = 0;
        for (Addr ad : parsed) {
            int remaining = limit - count;
            if (remaining <= 0) break;
            IndexStore.Outpoint cursor = after;
            int taken = 0;
            while (taken <= remaining) {
                List<IndexStore.Outpoint> page = db.index().addressCoins(ad.version(), ad.hash(),
                        Math.min(IndexStore.MAX_PAGE, remaining + 1 - taken), cursor);
                if (page.isEmpty()) break;
                for (IndexStore.Outpoint op : page) {
                    cursor = op;
                    String idHex = ChainJson.hex(op.txid());
                    if (spent.contains(idHex + ":" + op.index())) continue;
                    ChainDB.UtxoEntry e = db.getUtxo(idHex, op.index());
                    if (e == null) continue;
                    if (++taken > remaining) {
                        if (explicit) break;
                        throw tooMany("/coin/address");
                    }
                    if (count++ > 0) sb.append(',');
                    sb.append(cj.utxoCoin(op.txid(), op.index(), e));
                }
                if (taken > remaining) break;
                if (page.size() < Math.min(IndexStore.MAX_PAGE, remaining + 1)) break;
            }
        }
        for (TxParser.ParsedTx t : mpTxs) {
            String idHex = ChainJson.hex(ChainJson.txid(t));
            for (int i = 0; i < t.outputs.size(); i++) {
                if (!matches(t.outputs.get(i), parsed) || spent.contains(idHex + ":" + i)) continue;
                if (count++ > 0) sb.append(',');
                sb.append(cj.mempoolCoin(t, i));
            }
        }
        return new Response(200, sb.append(']').toString());
    }

    // ── mempool / fee / broadcast ────────────────────────────────────────────

    private Response mempoolList() {
        StringBuilder sb = new StringBuilder("[");
        if (mempool != null) {
            boolean first = true;
            for (Mempool.MempoolEntry e : mempool.getAll()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(e.txid).append('"');
            }
        }
        return new Response(200, sb.append(']').toString());
    }

    private Response mempoolInvalid() {
        return new Response(200, "{\"items\":" + (mempool != null ? mempool.rejectCount() : 0)
                + ",\"size\":0,\"entries\":0,\"n\":0,\"limit\":" + Mempool.rejectLimit() + ",\"tweak\":0}");
    }

    private Response mempoolInvalidHash(String s) throws HttpError {
        hash32(s, "Hash");
        boolean bad = mempool != null && mempool.hasReject(s.toLowerCase());
        return new Response(200, "{\"invalid\":" + bad + "}");
    }

    private Response fee(java.util.Map<String, String> q) {
        long rate = 0;
        if (mempool != null) {
            List<Long> rates = new ArrayList<>();
            for (Mempool.MempoolEntry e : mempool.getAll()) rates.add(e.size == 0 ? 0 : e.fee * 1000 / e.size);
            if (!rates.isEmpty()) {
                java.util.Collections.sort(rates);
                rate = rates.get(rates.size() / 2);
            }
        }
        return new Response(200, "{\"rate\":" + rate + "}");
    }

    private Response broadcast(String body) throws HttpError {
        Matcher m = TX_FIELD.matcher(body == null ? "" : body);
        if (!m.find() || m.group(1).isEmpty()) throw new HttpError(400, "TX is required.");
        if (mempool == null) throw new HttpError(400, "Mempool not ready.");
        byte[] raw;
        try { raw = HexUtil.decode(m.group(1)); } catch (RuntimeException e) { throw new HttpError(400, "TX is required."); }
        try {
            mempool.submitOrThrow(raw);
        } catch (Mempool.VerifyException e) {
            throw new HttpError(400, e.reason);
        } catch (RuntimeException e) {
            throw new HttpError(400, "Failed to decode transaction.");
        }
        return new Response(200, "{\"success\":true}");
    }
}