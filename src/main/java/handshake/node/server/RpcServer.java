package handshake.node.server;

import handshake.node.util.HexUtil;
import handshake.node.util.NodeClock;
import handshake.node.util.JsonUtil;

import handshake.node.crypto.Blake2b;
import handshake.node.crypto.MerkleProof;
import handshake.node.crypto.Bech32;
import handshake.node.crypto.Base58;
import handshake.node.crypto.Secp256k1;
import handshake.node.crypto.MerkleUtil;

import handshake.node.storage.ChainDB;
import handshake.node.storage.IndexStore;
import handshake.node.chain.HandshakeCovenantRules;
import handshake.node.chain.ReservedNames;

import handshake.node.urkeltree.UrkelNameHash;
import handshake.node.urkeltree.UrkelProof;

import handshake.node.peer.PeerTable;
import handshake.node.peer.NodeIdentity;

import handshake.node.chain.BlockProcessor;
import handshake.node.chain.ChainSync;
import handshake.node.chain.BlockTemplates;
import handshake.node.chain.HeaderUtil;
import handshake.node.chain.Mempool;
import handshake.node.chain.P2pMessages;
import handshake.node.NodeConfig;
import handshake.node.chain.TxParser;
import handshake.node.chain.TxVerify;

import com.sun.net.httpserver.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * RpcServer — hsd-compatible JSON-RPC 1.0 HTTP server.
 * <p>
 * Exposes the same RPC interface as hsd so existing tools
 * (hs-client, hsd-rpc CLI, block explorers) work without modification.
 * <p>
 * This is intentionally a lean, RPC-only server -- no web dashboard, no
 * HTML/JS serving, no TLS. The validator's job is consensus, validation, and
 * storage; anything web-facing is a separate concern for a separate,
 * decoupled consumer (matching how the wallet was deliberately decoupled
 * from this project too) talking to the validator purely over RPC.
 * <p>
 * Endpoint:
 *   POST /          — JSON-RPC method calls
 * <p>
 * Authentication:
 *   HTTP Basic auth with username "x" and the configured API key.
 *   If no API key is configured, all requests are allowed.
 * <p>
 * Block notifications:
 *   Registered listeners are called on every new block for real-time updates.
 */
public class RpcServer {

    // ── State ─────────────────────────────────────────────────────────────────

    private final NodeConfig config;
    private final ChainDB    db;
    private HttpServer       server;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    // Block notification listeners (wallet app, DNS app etc register here)
    private final List<BlockListener> blockListeners = new CopyOnWriteArrayList<>();

    // Mempool reference — set by ChainSync when mempool is ready
    private volatile Mempool mempool;

    // ChainSync reference — set after sync starts
    private volatile ChainSync chainSync;

    // Request counter for logging
    private final AtomicLong requestCount = new AtomicLong();

    // ── Constructor ───────────────────────────────────────────────────────────

    public RpcServer(NodeConfig config, ChainDB db) {
        this.config = config;
        this.db     = db;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() throws IOException {
        InetSocketAddress addr = new InetSocketAddress(
                config.getRpcHost(), config.getRpcPort());
        server = HttpServer.create(addr, 32);
        server.createContext("/", this::handle);
        server.setExecutor(executor);
        server.start();
    }

    public void stop() {
        if (server != null) server.stop(2);
        executor.shutdown();
    }

    public void setMempool(Mempool mempool)     { this.mempool   = mempool; }
    public void setChainSync(ChainSync sync)    { this.chainSync = sync; }

    // ── Block notifications ───────────────────────────────────────────────────

    public interface BlockListener {
        void onNewBlock(int height, byte[] hash, byte[] rawBlock);

        /** A block that was part of our chain has been undone by a reorganization
         *  (called newest-first, before the replacement blocks are announced). */
        default void onBlockDisconnected(int height, byte[] hash, byte[] rawBlock) {}
    }

    public void addBlockListener(BlockListener listener) {
        blockListeners.add(listener);
    }

    public void notifyNewBlock(int height, byte[] hash, byte[] rawBlock) {
        for (BlockListener l : blockListeners) {
            try { l.onNewBlock(height, hash, rawBlock); }
            catch (Exception e) {
                System.err.println("[RPC] Block listener error: " + e.getMessage());
            }
        }
    }

    public void notifyBlockDisconnected(int height, byte[] hash, byte[] rawBlock) {
        for (BlockListener l : blockListeners) {
            try { l.onBlockDisconnected(height, hash, rawBlock); }
            catch (Exception e) {
                System.err.println("[RPC] Block listener error: " + e.getMessage());
            }
        }
    }

    // ── HTTP handler ──────────────────────────────────────────────────────────

    private void handle(HttpExchange ex) throws IOException {
        try {
            // Auth check
            if (config.hasApiKey() && !checkAuth(ex)) {
                respond(ex, 401, "{\"error\":\"Unauthorized\"}");
                return;
            }

            String method = ex.getRequestMethod();

            String path = ex.getRequestURI().getPath();
            if ("POST".equals(method) && !RestApi.isRestPath(method, path)) {
                handleRpc(ex);
            } else if ("GET".equals(method) || "POST".equals(method)) {
                handleRest(ex, method, path);
            } else if ("OPTIONS".equals(method)) {
                ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
                ex.sendResponseHeaders(204, -1);
            } else {
                respond(ex, 404, "");
            }
        } catch (Exception e) {
            System.err.println("[RPC] Handler error: " + e.getMessage());
            respond(ex, 500, "{\"error\":\"Internal error\"}");
        } finally {
            ex.close();
        }
    }

    private volatile RestApi rest;

    private RestApi rest() {
        RestApi r = rest;
        if (r == null) {
            synchronized (this) {
                if (rest == null) rest = new RestApi(db, mempool, chainSync, config);
                r = rest;
            }
        }
        return r;
    }

    private void handleRest(HttpExchange ex, String method, String path) throws IOException {
        requestCount.incrementAndGet();
        String body = "POST".equals(method)
                ? new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8) : "";
        RestApi.Response r;
        if ("POST".equals(method) && path.equals("/reset")) r = restReset(body);
        else r = rest().handle(method, path, ex.getRequestURI().getRawQuery(), body);
        respond(ex, r.status(), r.body());
    }

    private void handleRpc(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requestCount.incrementAndGet();
        respond(ex, 200, processRpcRequest(body));
    }

    /**
     * Processes a JSON-RPC request body and returns the JSON-RPC response
     * body, with no dependency on HttpExchange or any particular
     * transport -- this is what lets WebServer's own "/" endpoint (for
     * the dashboard's API Explorer, which expects same-origin POST /
     * per its existing, unmodified app.js) call directly into this same
     * dispatch logic in-process, rather than needing a second HTTP hop
     * back to this server's own dedicated port.
     */
    public String processRpcRequest(String body) {
        try {
            String rpcMethod = extractString(body, "method");
            String id        = extractId(body);
            String params    = extractParams(body);

            if (rpcMethod == null) {
                return error(id, -32600, "Invalid request");
            }

            String result = dispatch(rpcMethod, params);
            return success(id, result);

        } catch (RpcException e) {
            String id = extractId(body);
            return error(id, e.code, e.getMessage());
        } catch (Exception e) {
            String id = extractId(body);
            return error(id, -32603, e.getMessage());
        }
    }

    /**
     * The single, authoritative list of every RPC method this server
     * handles -- extracted programmatically from the actual dispatch()
     * switch cases below, not hand-maintained separately. help() is
     * generated FROM this array, specifically so it can't independently
     * go stale the way it previously did (missing getnameresource,
     * verifymessagewithname, getnameproof, and others, despite all of
     * them being real, working methods).
     *
     * This array itself still needs a manual entry whenever a new case
     * is added to dispatch() -- Java's switch doesn't support building
     * case labels from a runtime array, so full elimination of that step
     * isn't possible without replacing the switch with a method-name-to-
     * handler map entirely (a much larger change touching all 53
     * existing, working methods, not undertaken here). What this DOES
     * fix is the actual, confirmed problem: help() drifting silently out
     * of sync with reality. A test (see RpcMethodListTest, run manually,
     * not part of the build) parses this file's real dispatch() cases
     * and confirms this array matches them exactly in both directions.
     *
     * FIX: a second, separate drift risk existed alongside this one --
     * WebAdminServerContent's own RPC_METHODS_JS (the richer, per-
     * parameter metadata list the admin UI's dropdown/form is built
     * from) is hand-maintained independently of this array, with nothing
     * keeping the two in sync. Generating RPC_METHODS_JS's JS object
     * literal FROM this array at runtime was considered and rejected
     * here: RPC_METHODS_JS carries real per-parameter metadata (names,
     * types, which are required, defaults) this array has no equivalent
     * of, so "generate one from the other" would mean inventing a new
     * Java-side metadata model for every one of the 53 methods just to
     * re-derive a JS literal that already exists and is already correct
     * -- a much larger, higher-risk change than this cleanup pass
     * intended, for a form of drift that's cosmetic (a stale admin UI
     * dropdown) rather than a working-method/consensus risk. Instead,
     * RpcMethodListSyncTest (same manual-run convention as
     * RpcMethodListTest, in the same package) cross-checks this array's
     * method names against RPC_METHODS_JS's own keys in both directions,
     * so a drift between them is at least discoverable by running the
     * test, rather than silently invisible the way it was before.
     */
    static final String[] RPC_METHODS = {
            "addnode",
            "clearbanned",
            "createmultisig",
            "createrawtransaction",
            "decoderawtransaction",
            "decodescript",
            "disconnectnode",
            "estimatefee",
            "estimatesmartfee",
            "getaddednodeinfo",
            "getbestblockhash",
            "getblock",
            "getblockbyheight",
            "getblockchaininfo",
            "getblockcount",
            "getblockhash",
            "getblockheader",
            "getblocktemplate",
            "getchaintips",
            "getconnectioncount",
            "getdifficulty",
            "getinfo",
            "generate",
            "generatetoaddress",
            "getgenerate",
            "getmemoryinfo",
            "getmininginfo",
            "getmineraddress",
            "getnetworkhashps",
            "getwork",
            "getworklp",
            "getmempoolancestors",
            "getmempooldescendants",
            "getmempoolentry",
            "getmempoolinfo",
            "getnamebyhash",
            "getnameinfo",
            "getnameproof",
            "getnameresource",
            "getnames",
            "getnettotals",
            "getnetworkinfo",
            "getpeerinfo",
            "getrawmempool",
            "getrawtransaction",
            "gettxout",
            "gettxoutproof",
            "gettxoutsetinfo",
            "help",
            "listbanned",
            "ping",
            "prioritisetransaction",
            "pruneblockchain",
            "sendrawtransaction",
            "setban",
            "setmocktime",
            "compacttree",
            "decoderesource",
            "estimatepriority",
            "estimatesmartpriority",
            "getdnssecproof",
            "grindname",
            "invalidateblock",
            "reconsiderblock",
            "reconstructtree",
            "resetrootcache",
            "sendrawairdrop",
            "sendrawclaim",
            "setloglevel",
            "setmineraddress",
            "signrawtransaction",
            "validateresource",
            "verifychain",
            "setgenerate",
            "signmessagewithprivkey",
            "stop",
            "submitblock",
            "submitwork",
            "validateaddress",
            "verifyblock",
            "verifymessage",
            "verifymessagewithname",
            "verifytxoutproof"
    };

    // ── Method dispatch ───────────────────────────────────────────────────────

    private String dispatch(String method, String params) throws RpcException {
        return switch (method) {
            // Chain
            case "getblockcount"      -> getBlockCount();
            case "getblockhash"       -> getBlockHash(params);
            case "getblockheader"     -> getBlockHeader(params);
            case "getblocktemplate"   -> getBlockTemplate(params);
            case "submitblock"        -> submitBlock(params);
            case "getblock"           -> getBlock(params);
            case "getblockbyheight"   -> getBlockByHeight(params);
            case "getbestblockhash"   -> getBestBlockHash();
            case "getblockchaininfo"  -> getBlockchainInfo();
            case "getdifficulty"      -> getDifficulty();
            case "getchaintips"       -> getChainTips();
            case "verifyblock"        -> verifyBlock(params);

            // Mining
            case "getwork"            -> mining().getWork();
            case "getworklp"          -> mining().getWorkLongpoll();
            case "submitwork"         -> submitWork(params);
            case "getmininginfo"      -> mining().getMiningInfo(this);
            case "getnetworkhashps"   -> getNetworkHashPS(params);
            case "setmocktime"        -> setMockTime(params);
            case "compacttree"        -> noArgsNull(params, "compacttree");
            case "reconstructtree"    -> noArgsNull(params, "reconstructtree");
            case "resetrootcache"     -> noArgsNull(params, "resetrootcache");
            case "verifychain"        -> verifyChain(params);
            case "estimatepriority"   -> estimatePriority(params, false);
            case "estimatesmartpriority" -> estimatePriority(params, true);
            case "invalidateblock"    -> invalidateBlock(params, true);
            case "reconsiderblock"    -> invalidateBlock(params, false);
            case "decoderesource"     -> decodeResource(params);
            case "validateresource"   -> validateResource(params);
            case "getdnssecproof"     -> throw new RpcException(-1, "DNSSEC proofs need a recursive resolver, which this node does not include.");
            case "sendrawclaim"       -> throw new RpcException(-1, "This node keeps no claim pool; claims are not supported.");
            case "sendrawairdrop"     -> throw new RpcException(-1, "This node keeps no airdrop pool; airdrop proofs are not supported.");
            case "grindname"          -> grindName(params);
            case "setloglevel"        -> setLogLevel(params);
            case "getmineraddress"    -> jsonString(config.getMinerAddress());
            case "setmineraddress"    -> setMinerAddress(params);
            case "signrawtransaction" -> signRawTransaction(params);
            case "getgenerate"        -> String.valueOf(mining().isGenerating());
            case "setgenerate"        -> setGenerate(params);
            case "generate"           -> generate(params);
            case "generatetoaddress"  -> generateToAddress(params);

            // Transactions
            case "getrawtransaction"    -> getRawTransaction(params);
            case "decoderawtransaction" -> decodeRawTransaction(params);
            case "decodescript"         -> decodeScript(params);
            case "createrawtransaction" -> createRawTransaction(params);
            case "sendrawtransaction"   -> sendRawTransaction(params);
            case "gettxout"             -> getTxOut(params);
            case "gettxoutproof"        -> getTxOutProof(params);
            case "verifytxoutproof"     -> verifyTxOutProof(params);

            // Mempool
            case "getrawmempool"   -> getRawMempool(params);
            case "getmempoolentry" -> getMempoolEntry(params);
            case "getmempoolinfo"  -> getMempoolInfo();
            case "gettxoutsetinfo" -> getTxOutSetInfo();
            case "estimatefee"     -> estimateFee(params);
            case "estimatesmartfee" -> estimateSmartFee(params);
            case "getmempoolancestors"   -> getMempoolAncestors(params);
            case "getmempooldescendants" -> getMempoolDescendants(params);
            case "prioritisetransaction" -> prioritiseTransaction(params);

            // Names
            case "getnameinfo"     -> getNameInfo(params);
            case "getnameproof"    -> getNameProof(params);
            case "getnameresource" -> getNameResource(params);
            case "getnamebyhash"   -> getNameByHash(params);
            case "getnames"        -> getNames();

            // Node
            case "getinfo"         -> getInfo();
            case "getnetworkinfo"  -> getNetworkInfo();
            case "getpeerinfo"     -> getPeerInfo();
            case "getconnectioncount" -> getConnectionCount();
            case "ping"             -> ping();
            case "setban"           -> setBan(params);
            case "listbanned"       -> listBanned();
            case "clearbanned"      -> clearBanned();
            case "getnettotals"     -> getNetTotals();
            case "addnode"          -> addNode(params);
            case "disconnectnode"   -> disconnectNode(params);
            case "getaddednodeinfo" -> getAddedNodeInfo(params);
            case "getmemoryinfo"    -> getMemoryInfo();
            case "pruneblockchain"  -> pruneBlockchain();
            case "createmultisig"   -> createMultisig(params);
            case "stop"            -> stopNode();
            case "help"            -> help();
            case "validateaddress" -> validateAddress(params);
            case "signmessagewithprivkey"  -> signMessageWithPrivkey(params);
            case "verifymessage"           -> verifyMessage(params);
            case "verifymessagewithname"   -> verifyMessageWithName(params);

            default -> throw new RpcException(-32601,
                    "Method not found: " + method);
        };
    }

    // ── Mining RPCs (see MiningService) ───────────────────────────────────────

    private MiningService miningService;

    private synchronized MiningService mining() throws RpcException {
        if (chainSync == null) throw new RpcException(-1, "Node not ready");
        if (miningService == null) {
            miningService = new MiningService(config, db, chainSync, mempool);
            addBlockListener(miningService);
        }
        return miningService;
    }

    private String submitWork(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.isEmpty() || pl.size() > 2) throw new RpcException(-1, "submitwork ( \"data\" \"mask\" )");
        byte[] data, mask = new byte[32];
        try { data = fromHex(pl.get(0).trim()); } catch (Exception e) { throw new RpcException(-3, "Invalid work data."); }
        if (pl.size() == 2) {
            try { mask = fromHex(pl.get(1).trim()); } catch (Exception e) { throw new RpcException(-3, "Invalid mask."); }
            if (mask.length != 32) throw new RpcException(-3, "Invalid mask.");
        }
        return mining().submitWork(data, mask);
    }

    private String getNetworkHashPS(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.size() > 2) throw new RpcException(-1, "getnetworkhashps ( blocks height )");
        int lookup = pl.size() > 0 ? parseIntParam(params, 0) : 120;
        int height = pl.size() > 1 ? parseIntParam(params, 1) : -1;
        if (lookup < 0 || (pl.size() > 1 && height < 0)) throw new RpcException(-8, "Invalid parameter.");
        return number(mining().getHashRate(lookup, height));
    }

    private String setMockTime(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.size() != 1) throw new RpcException(-1, "setmocktime timestamp");
        long ts;
        try { ts = Long.parseLong(parseStringParam(params, 0).trim()); } catch (Exception e) { throw new RpcException(-3, "Invalid timestamp."); }
        if (ts < 0 || ts > 0xFFFFFFFFL) throw new RpcException(-3, "Invalid timestamp.");
        NodeClock.setMockTime(ts);
        return "null";
    }

    private String setGenerate(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.isEmpty() || pl.size() > 2) throw new RpcException(-1, "setgenerate mine ( proclimit )");
        int limit = pl.size() > 1 ? parseIntParam(params, 1) : 0;
        return mining().setGenerate(parseBoolParam(params, 0, false), Math.max(limit, 0));
    }

    private String generate(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.isEmpty() || pl.size() > 2) throw new RpcException(-1, "generate numblocks ( maxtries )");
        int blocks = parseIntParam(params, 0);
        long tries = pl.size() > 1 ? parseIntParam(params, 1) : 0;
        if (blocks < 0) throw new RpcException(-8, "Invalid number of blocks.");
        return mining().generate(blocks, null, tries);
    }

    private String generateToAddress(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.size() < 2 || pl.size() > 3) throw new RpcException(-1, "generatetoaddress numblocks address ( maxtries )");
        int blocks = parseIntParam(params, 0);
        String addr = parseStringParam(params, 1);
        long tries = pl.size() > 2 ? parseIntParam(params, 2) : 0;
        if (blocks < 0) throw new RpcException(-8, "Invalid number of blocks.");
        return mining().generate(blocks, addr, tries);
    }

    // ── RPC method implementations ────────────────────────────────────────────

    private String getBlockCount() {
        return String.valueOf(db.getBlockTip());
    }

    private String getBestBlockHash() throws RpcException {
        int tip = db.getBlockTip();
        byte[] header = db.getHeader(tip);
        if (header == null) throw new RpcException(-5, "No block data");
        return "\"" + hex(HeaderUtil.hash(header)) + "\"";
    }

    private String getBlockHash(String params) throws RpcException {
        int height = parseIntParam(params, 0);
        byte[] header = height < 0 || height > db.getBlockTip() ? null : db.getHeader(height);
        if (header == null) throw new RpcException(-8, "Block height out of range.");
        return "\"" + hex(HeaderUtil.hash(header)) + "\"";
    }

    private String getBlockHeader(String params) throws RpcException {
        String hashOrHeight = parseStringParam(params, 0);
        byte[] header = resolveHeader(hashOrHeight);
        if (header == null) throw new RpcException(-5, "Block header not found");
        boolean verbose = parseBoolParam(params, 1, true);
        if (!verbose) return "\"" + hex(header) + "\"";
        int height = resolveHeight(hashOrHeight);
        return headerToJson(header, height);
    }

    private String getBlock(String params) throws RpcException {
        String hashOrHeight = parseStringParam(params, 0);
        if (hashOrHeight == null || !(hashOrHeight.matches("[0-9a-fA-F]{64}") || hashOrHeight.matches("\\d{1,9}")))
            throw new RpcException(-3, "Param #0 must be a hash.");
        int height;
        try { height = resolveHeight(hashOrHeight); }
        catch (RpcException e) { throw new RpcException(-1, "Block not found."); }
        if (height > db.getBlockTip()) throw new RpcException(-1, "Block not found.");
        byte[] rawBlock = db.getBlock(height);
        if (rawBlock == null) throw new RpcException(-5,
                "Block not found: " + hashOrHeight);
        boolean verbose = parseBoolParam(params, 1, true);
        if (!verbose) return "\"" + hex(rawBlock) + "\"";
        return blockToJson(rawBlock, height, parseBoolParam(params, 2, false));
    }

    private String getRawTransaction(String params) throws RpcException {
        String txid = parseStringParam(params, 0);
        if (txid == null || !txid.matches("[0-9a-fA-F]{64}")) throw new RpcException(-3, "Param #0 must be a hash.");
        boolean verbose = parseBoolParam(params, 1, false);
        byte[] raw = null;
        String blockHash = null;
        long blockTime = 0, mtime = 0;
        int height = -1;
        if (mempool != null) {
            raw = mempool.getRaw(txid);
            Mempool.MempoolEntry me = raw == null ? null : mempool.getEntry(txid);
            if (me != null) mtime = me.addedAt / 1000;
        }
        if (raw == null) {
            try {
                ChainJson cj = new ChainJson(db, mempool);
                byte[] id = fromHex(txid);
                IndexStore.TxLoc loc = cj.locate(id);
                TxParser.ParsedTx t = loc == null ? null : cj.txAt(loc, id);
                if (t != null && loc.height() <= db.getBlockTip()) {
                    raw = t.raw;
                    height = loc.height();
                    byte[] hd = db.getHeader(height);
                    blockHash = hex(HeaderUtil.hash(hd));
                    blockTime = HeaderUtil.time(hd);
                    mtime = blockTime;
                }
            } catch (RuntimeException ignored) { }
        }
        if (raw == null) {
            if (db.index() == null) throw new RpcException(-5, "No tx index is available.");
            throw new RpcException(-5, "Transaction not found.");
        }
        if (!verbose) return "\"" + hex(raw) + "\"";
        TxParser.ParsedTx tx = TxParser.parse(raw);
        if (tx == null) throw new RpcException(-22, "Failed to parse transaction");
        String j = rpcTx(tx, blockHash, blockTime, height);
        // hsd: time = when the node first saw it, blocktime = the block's; hex appended last
        if (blockHash != null || mtime != 0) j = j.replaceFirst("\"time\":\\d+,", "\"time\":" + mtime + ",");
        return j.substring(0, j.length() - 1) + ",\"hex\":\"" + hex(raw) + "\"}";
    }

    private String decodeRawTransaction(String params) throws RpcException {
        String hexTx = parseStringParam(params, 0);
        byte[] raw;
        try { raw = fromHex(hexTx == null ? "" : hexTx); } catch (RuntimeException e) { throw new RpcException(-3, "Param #0 must be a hex string."); }
        if (raw.length == 0) throw new RpcException(-3, "Param #0 must be a hex string.");
        TxParser.ParsedTx tx = TxParser.parse(raw);
        if (tx == null) throw new RpcException(-22, "TX decode failed");
        return rpcTx(tx, null, 0, -1);
    }

    /** Shared by getrawtransaction (verbose) and decoderawtransaction. */
    private String txToJson(TxParser.ParsedTx tx, byte[] raw) {
        String txid = TxParser.computeTxid(raw);
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"txid\":\"").append(txid).append("\",");
        sb.append("\"version\":").append(tx.version).append(",");
        sb.append("\"locktime\":").append(tx.locktime).append(",");
        sb.append("\"size\":").append(raw.length).append(",");
        sb.append("\"hex\":\"").append(hex(raw)).append("\",");

        sb.append("\"vin\":[");
        for (int i = 0; i < tx.inputs.size(); i++) {
            if (i > 0) sb.append(",");
            TxParser.Input in = tx.inputs.get(i);
            sb.append("{");
            if (in.isCoinbase()) {
                sb.append("\"coinbase\":true");
            } else {
                sb.append("\"txid\":\"").append(in.prevTxid).append("\",");
                sb.append("\"vout\":").append(in.prevIndex).append(",");
                sb.append("\"sequence\":").append(in.sequence);
            }
            sb.append("}");
        }
        sb.append("],");

        sb.append("\"vout\":[");
        for (int i = 0; i < tx.outputs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(outputToJson(tx.outputs.get(i), i));
        }
        sb.append("]");
        sb.append("}");
        return sb.toString();
    }

    private String outputToJson(TxParser.Output out, int index) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"value\":").append(out.value / 1_000_000.0).append(",");
        sb.append("\"n\":").append(index).append(",");
        sb.append("\"address\":{");
        sb.append("\"version\":").append(out.addrVersion).append(",");
        sb.append("\"hash\":\"").append(hex(out.addrHash)).append("\"");
        sb.append("},");
        sb.append("\"covenant\":{");
        sb.append("\"type\":").append(out.covenant.type).append(",");
        sb.append("\"action\":\"").append(covenantActionName(out.covenant.type)).append("\",");
        sb.append("\"items\":[");
        for (int j = 0; j < out.covenant.items.size(); j++) {
            if (j > 0) sb.append(",");
            sb.append("\"").append(hex(out.covenant.items.get(j).data)).append("\"");
        }
        sb.append("]}");
        sb.append("}");
        return sb.toString();
    }

    private static String covenantActionName(int type) {
        return switch (type) {
            case TxParser.COV_NONE   -> "NONE";
            case TxParser.COV_CLAIM  -> "CLAIM";
            case TxParser.COV_OPEN   -> "OPEN";
            case TxParser.COV_BID    -> "BID";
            case TxParser.COV_REVEAL -> "REVEAL";
            case TxParser.COV_REDEEM -> "REDEEM";
            case TxParser.COV_REGISTER -> "REGISTER";
            case TxParser.COV_UPDATE   -> "UPDATE";
            case TxParser.COV_RENEW    -> "RENEW";
            case TxParser.COV_TRANSFER -> "TRANSFER";
            case TxParser.COV_FINALIZE -> "FINALIZE";
            case TxParser.COV_REVOKE   -> "REVOKE";
            default -> "UNKNOWN";
        };
    }

    private String sendRawTransaction(String params) throws RpcException {
        String hexTx = parseStringParam(params, 0);
        if (hexTx == null || hexTx.isEmpty())
            throw new RpcException(-22, "Missing raw transaction");
        byte[] raw = fromHex(hexTx);
        if (mempool == null) throw new RpcException(-1, "Mempool not ready");
        try {
            return "\"" + mempool.submitOrThrow(raw) + "\"";
        } catch (Mempool.VerifyException e) {
            throw new RpcException(-26, e.reason);
        } catch (RuntimeException e) {
            throw new RpcException(-22, "TX decode failed");
        }
    }

    private String getTxOut(String params) throws RpcException {
        String txid = parseStringParam(params, 0);
        if (txid == null || !txid.matches("[0-9a-fA-F]{64}")) throw new RpcException(-3, "Invalid outpoint.");
        int index;
        try { index = parseIntParam(params, 1); } catch (RpcException e) { throw new RpcException(-3, "Invalid outpoint."); }
        if (index < 0) throw new RpcException(-3, "Invalid outpoint.");
        boolean includeMempool = parseBoolParam(params, 2, true);
        txid = txid.toLowerCase();
        byte[] id = fromHex(txid);
        if (includeMempool && mempool != null) {
            byte[] mraw = mempool.getRaw(txid);
            if (mraw != null) {
                TxParser.ParsedTx t = TxParser.parse(mraw);
                if (t == null || index >= t.outputs.size()) return "null";
                for (Mempool.MempoolEntry e : mempool.getAll()) {
                    TxParser.ParsedTx o = TxParser.parse(e.raw);
                    if (o == null) continue;
                    for (TxParser.Input in : o.inputs)
                        if (in.prevIndex == index && Arrays.equals(in.prevHash, id)) return "null";
                }
                TxParser.Output out = t.outputs.get(index);
                return coinOutJson(out.value, out.addrVersion, out.addrHash, t.version, false, -1);
            }
            for (Mempool.MempoolEntry e : mempool.getAll()) {   // a chain coin already spent in the mempool is gone
                TxParser.ParsedTx o = TxParser.parse(e.raw);
                if (o == null) continue;
                for (TxParser.Input in : o.inputs)
                    if (in.prevIndex == index && Arrays.equals(in.prevHash, id)) return "null";
            }
        }
        ChainDB.UtxoEntry utxo = db.getUtxo(txid, index);
        if (utxo == null) return "null";
        return coinOutJson(utxo.value(), utxo.addrVersion(), utxo.addrHash(), 0, utxo.coinbase(), utxo.height());
    }

    private String getRawMempool(String params) throws RpcException {
        if (mempool == null) return "[]";
        boolean verbose = parseBoolParam(params, 0, false);
        return mempool.toJson(verbose);
    }

    private String getMempoolEntry(String params) throws RpcException {
        String txid = parseStringParam(params, 0);
        if (mempool == null) throw new RpcException(-5, "Mempool not ready");
        String entry = mempool.getEntryJson(txid);
        if (entry == null) throw new RpcException(-5,
                "Transaction not in mempool: " + txid);
        return entry;
    }

    /**
     * Matches real hsd's getnameresource shape exactly:
     * {"records": [{"type": "NS", ...}, {"type": "GLUE4", ...}, ...]}.
     * Returns an empty records array (not an error) for a name with no
     * UPDATE/REGISTER covenant data yet -- a name that simply hasn't set
     * any records isn't a failure case.
     */
    private String getNameResource(String params) throws RpcException {
        String name = parseStringParam(params, 0);
        if (name == null || name.isEmpty())
            throw new RpcException(-8, "Name required");
        byte[] nameHash = UrkelNameHash.hashName(name); // SHA3-256, confirmed against real hsd -- was incorrectly Blake2b
        ChainDB.NameEntry entry = db.getNameByHash(nameHash);
        if (entry == null || entry.resourceData == null || entry.resourceData.length == 0) {
            return "{\"records\":[]}";
        }
        return DnsResource.decodeToJson(entry.resourceData);
    }

    /** "handshake signed message:\n" -- confirmed directly against real
     *  hsd source (lib/pkg.js's pkg.currency = 'handshake', combined
     *  with rpc.js's own MAGIC_STRING template). This exact prefix
     *  matters: getting it wrong would mean signatures produced here
     *  silently fail to verify against real hsd/wallet software, and
     *  vice versa, without any obvious error. */
    private static final String MAGIC_STRING = "handshake signed message:\n";

    private static byte[] messageHash(String message) {
        byte[] msg = (MAGIC_STRING + message).getBytes(StandardCharsets.UTF_8);
        return Blake2b.hash(msg, 32);
    }

    /**
     * Matches real hsd's signmessagewithprivkey: WIF-decodes the given
     * private key, signs Blake2b(MAGIC_STRING + message), returns the
     * raw 64-byte (r||s) signature as base64 -- confirmed against a
     * real example in the official docs decoding to exactly 64 bytes,
     * not DER, with no embedded recovery id.
     */
    private String signMessageWithPrivkey(String params) throws RpcException {
        String wif = parseStringParam(params, 0);
        String message = parseStringParam(params, 1);
        if (wif == null || message == null)
            throw new RpcException(-1, "signmessagewithprivkey \"privkey\" \"message\"");

        byte[] privateKey;
        try {
            byte[] payload = Base58.decodeCheck(wif);
            // payload = version(1) + privkey(32) + compression-flag(1)
            if (payload.length < 33) throw new IllegalArgumentException("Invalid WIF payload length");
            privateKey = Arrays.copyOfRange(payload, 1, 33);
        } catch (Exception e) {
            throw new RpcException(-5, "Invalid key.");
        }

        byte[] hash = messageHash(message);
        byte[] sig = Secp256k1.sign(hash, privateKey);
        return "\"" + Base64.getEncoder().encodeToString(sig) + "\"";
    }

    /**
     * Matches real hsd's verifymessage: recovers the signer's public key
     * from the signature (trying all 4 recovery ids, since none is
     * embedded) and checks whether its Blake2b-160 hash matches the
     * given address's hash. Only handles standard 20-byte P2PKH
     * addresses, matching real hsd's own check (addr.version !== 0 ||
     * addr.hash.length !== 20 -> false) before even attempting recovery.
     */
    private String verifyMessage(String params) throws RpcException {
        String addrStr = parseStringParam(params, 0);
        String sigB64 = parseStringParam(params, 1);
        String message = parseStringParam(params, 2);
        if (addrStr == null || sigB64 == null || message == null)
            throw new RpcException(-1, "verifymessage \"address\" \"signature\" \"message\"");

        Object[] decoded;
        try {
            decoded = Bech32.decode(addrStr);
        } catch (Exception e) {
            return "false";
        }
        int version = (int) decoded[1];
        byte[] addrHash = (byte[]) decoded[2];
        if (version != 0 || addrHash.length != 20) return "false";

        return verifySigAgainstAddrHash(message, sigB64, addrHash) ? "true" : "false";
    }

    /**
     * Matches real hsd's verifymessagewithname: looks up the name's
     * current owner UTXO and verifies the message against that address,
     * rather than a directly-supplied one.
     */
    private String verifyMessageWithName(String params) throws RpcException {
        String name = parseStringParam(params, 0);
        String sigB64 = parseStringParam(params, 1);
        String message = parseStringParam(params, 2);
        if (name == null || sigB64 == null || message == null)
            throw new RpcException(-1, "verifymessagewithname \"name\" \"signature\" \"message\"");

        byte[] nameHash = UrkelNameHash.hashName(name); // SHA3-256, confirmed against real hsd -- was incorrectly Blake2b
        ChainDB.NameEntry entry = db.getNameByHash(nameHash);
        if (entry == null || entry.ownerTxid == null)
            throw new RpcException(-1, "Cannot find the name owner.");

        ChainDB.UtxoEntry owner = db.getUtxo(entry.ownerTxid, entry.ownerIndex);
        if (owner == null)
            throw new RpcException(-20, "Cannot find the owner's address.");
        if (owner.addrHash().length != 20) return "false";

        return verifySigAgainstAddrHash(message, sigB64, owner.addrHash()) ? "true" : "false";
    }

    /**
     * RE-ARCHITECTURE: verifyMessage() and verifyMessageWithName() used to
     * each carry their own, line-for-line identical copy of this
     * signature-recovery loop (base64-decode the signature, hash the
     * message, try all 4 recovery IDs, compare the recovered pubkey's
     * address hash against the target) -- differing only in where the
     * target address hash came from (a directly-supplied address vs. a
     * name's current owner UTXO). Pulled out here so there's exactly one
     * place this verification logic can drift between the two RPCs.
     */
    private boolean verifySigAgainstAddrHash(String message, String sigB64, byte[] targetAddrHash) {
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(sigB64);
        } catch (Exception e) {
            return false;
        }
        if (sig.length != 64) return false;

        byte[] hash = messageHash(message);
        for (int i = 0; i < 4; i++) {
            byte[] recoveredPubKey = Secp256k1.recover(hash, sig, i);
            if (recoveredPubKey == null) continue;
            byte[] recoveredHash = Blake2b.hash(recoveredPubKey, 20);
            if (Arrays.equals(recoveredHash, targetAddrHash)) return true;
        }
        return false;
    }

    /**
     * getnameproof "name" ("root") -- matches real hsd's own RPC
     * exactly, confirmed directly from rpc.js's getNameProof: proves
     * against the LAST COMMITTED root (real hsd uses
     * this.chain.tip.treeRoot -- the header's own field, not a live,
     * uncommitted tree), not the tree's current live state, since a
     * proof only means anything if it's checkable against a root that
     * genuinely exists in an already-mined header.
     *
     * The optional second argument (prove against a SPECIFIC historical
     * root) isn't supported yet -- this tree is in-memory only and
     * doesn't keep historical snapshots beyond the current committed
     * one (see UrkelTree's own class comment), so a caller asking for
     * anything other than the current committed root gets a clear
     * error rather than a silently wrong answer.
     */
    private String getNameProof(String params) throws RpcException {
        String name = parseStringParam(params, 0);
        if (name == null || name.isEmpty())
            throw new RpcException(-8, "getnameproof \"name\" (\"root\")");

        String requestedRootHex = parseStringParam(params, 1);

        byte[] nameHash = UrkelNameHash.hashName(name);
        byte[] committedRoot = db.getNameTree().committedRoot();

        if (requestedRootHex != null && !requestedRootHex.isEmpty()
                && !requestedRootHex.equalsIgnoreCase(hex(committedRoot))) {
            throw new RpcException(-8,
                    "Proving against a specific historical root isn't supported yet -- "
                            + "only the current committed root (" + hex(committedRoot) + ") can be proved against.");
        }

        int tipHeight = db.getHeaderTip();
        byte[] tipHeader = tipHeight >= 0 ? db.getHeader(tipHeight) : null;
        String tipHashHex = tipHeader != null ? hex(HeaderUtil.hash(tipHeader)) : hex(new byte[32]);

        UrkelProof proof = db.getNameTree().proveCommitted(nameHash);

        StringBuilder sb = new StringBuilder("{");
        sb.append("\"hash\":\"").append(tipHashHex).append("\",");
        sb.append("\"height\":").append(tipHeight).append(",");
        sb.append("\"root\":\"").append(hex(committedRoot)).append("\",");
        sb.append("\"name\":\"").append(jsonEscape(name)).append("\",");
        sb.append("\"key\":\"").append(hex(nameHash)).append("\",");
        sb.append("\"proof\":").append(proofToJson(proof));
        sb.append("}");

        return "{\"result\":" + sb + "}";
    }

    /** Matches real Urkel's Proof.toJSON() exactly (confirmed directly
     *  from proof.js): a "type" name, depth, the collected sibling
     *  nodes as [prefixBitString, hashHex] pairs, and then only
     *  whichever extra fields that proof TYPE actually carries --
     *  matching JS's own behavior of omitting undefined fields rather
     *  than serializing them as null. */
    private String proofToJson(UrkelProof proof) {
        String typeName = switch (proof.type) {
            case UrkelProof.TYPE_DEADEND -> "TYPE_DEADEND";
            case UrkelProof.TYPE_SHORT -> "TYPE_SHORT";
            case UrkelProof.TYPE_COLLISION -> "TYPE_COLLISION";
            case UrkelProof.TYPE_EXISTS -> "TYPE_EXISTS";
            default -> "TYPE_UNKNOWN";
        };

        StringBuilder sb = new StringBuilder("{");
        sb.append("\"type\":\"").append(typeName).append("\",");
        sb.append("\"depth\":").append(proof.depth).append(",");

        sb.append("\"nodes\":[");
        for (int i = 0; i < proof.nodes.size(); i++) {
            if (i > 0) sb.append(",");
            UrkelProof.ProofNode pn = proof.nodes.get(i);
            sb.append("[\"").append(pn.prefix.toString()).append("\",\"").append(hex(pn.hash)).append("\"]");
        }
        sb.append("]");

        switch (proof.type) {
            case UrkelProof.TYPE_SHORT -> {
                sb.append(",\"prefix\":\"").append(proof.prefix.toString()).append("\"");
                sb.append(",\"left\":\"").append(hex(proof.left)).append("\"");
                sb.append(",\"right\":\"").append(hex(proof.right)).append("\"");
            }
            case UrkelProof.TYPE_COLLISION -> {
                sb.append(",\"key\":\"").append(hex(proof.key)).append("\"");
                sb.append(",\"hash\":\"").append(hex(proof.hash)).append("\"");
            }
            case UrkelProof.TYPE_EXISTS -> sb.append(",\"value\":\"").append(hex(proof.value)).append("\"");
            default -> { /* TYPE_DEADEND carries no extra fields */ }
        }

        sb.append("}");
        return sb.toString();
    }

    private String getNameInfo(String params) throws RpcException {
        String name = parseStringParam(params, 0);
        if (name == null || name.isEmpty())
            throw new RpcException(-8, "Name required");
        // Hash the name
        byte[] nameHash = UrkelNameHash.hashName(name); // SHA3-256, confirmed against real hsd -- was incorrectly Blake2b
        ChainDB.NameEntry entry = db.getNameByHash(nameHash);
        if (entry == null) {
            // Return empty/start info for names not yet in auction
            return "{\"result\":{\"start\":{\"reserved\":false,\"week\":0,"
                    + "\"start\":0,\"locked\":false},\"info\":null}}";
        }
        return nameEntryToJson(entry, name);
    }

    private String getNameByHash(String params) throws RpcException {
        String hashHex = parseStringParam(params, 0);
        if (hashHex == null || !hashHex.matches("[0-9a-fA-F]{64}")) throw new RpcException(-3, "Invalid name hash.");
        ChainDB.NameEntry entry = db.getNameByHash(hashHex.toLowerCase());
        if (entry == null) return "null";   // hsd answers null for an unknown name
        return "\"" + entry.name + "\"";
    }

    private String getInfo() {
        int tip = db.getBlockTip();
        byte[] th = tip >= 0 ? db.getHeader(tip) : null;
        int peers = chainSync != null ? chainSync.getConnectedPeerCount() : 0;
        boolean main = "main".equals(BlockProcessor.params.type);
        return "{"
                + "\"version\":\"" + NodeConfig.VERSION + "\","
                + "\"protocolversion\":3,"
                + "\"walletversion\":0,"
                + "\"balance\":0,"
                + "\"blocks\":" + tip + ","
                + "\"timeoffset\":" + NodeClock.offsetSec() + ","
                + "\"connections\":" + peers + ","
                + "\"proxy\":\"\","
                + "\"difficulty\":" + (th != null ? number(toDifficulty(HeaderUtil.bits(th))) : "0") + ","
                + "\"testnet\":" + !main + ","
                + "\"keypoololdest\":0,"
                + "\"keypoolsize\":0,"
                + "\"unlocked_until\":0,"
                + "\"paytxfee\":" + (main ? "0.1" : "0.02") + ","
                + "\"relayfee\":" + coinAmount(mempool != null ? mempool.getMinRelayFee() : 1000) + ","
                + "\"errors\":\"\""
                + "}";
    }

    /**
     * Matches real hsd's getnetworkinfo shape as closely as this
     * project's actual tracked data allows. "networks" (per-network-type
     * proxy/reachability info) and "localaddresses" (discovered external
     * addresses) are real hsd features this project doesn't implement --
     * both left as empty arrays rather than fabricated entries.
     */
    private String getNetworkInfo() {
        int peers = chainSync != null ? chainSync.getConnectedPeerCount() : 0;
        String comment = config.getUserAgentComment();
        String subversion = (comment == null || comment.isBlank())
                ? "/easy-handshake-node:" + NodeConfig.VERSION + "/"
                : "/easy-handshake-node:" + NodeConfig.VERSION + "/" + comment + "/";
        return "{"
                + "\"version\":\"" + NodeConfig.VERSION + "\","
                + "\"subversion\":\"" + subversion + "\","
                + "\"protocolversion\":70015,"
                + "\"localservices\":\"00000001\","
                + "\"localrelay\":true,"
                + "\"timeoffset\":0,"
                + "\"networkactive\":true,"
                + "\"connections\":" + peers + ","
                + "\"networks\":[],"
                + "\"relayfee\":" + (mempool != null ? mempool.getMinRelayFee() / 1_000_000.0 : 0.00001) + ","
                + "\"incrementalfee\":0,"
                + "\"localaddresses\":[],"
                + "\"warnings\":\"\""
                + "}";
    }

    private String getPeerInfo() {
        if (chainSync == null) return "[]";
        return chainSync.getPeerInfoJson();
    }

    private String getConnectionCount() {
        int peers = chainSync != null ? chainSync.getConnectedPeerCount() : 0;
        return String.valueOf(peers);
    }

    /** Matches real hsd's "ping" -- fire-and-forget, no direct response data. */
    private String ping() {
        // This project's PeerConnection objects are transient (opened per
        // sync batch, not held open indefinitely as a persistent pool),
        // so there's no live peer set to ping on demand the way hsd's
        // long-lived connection pool does. Real hsd's ping() itself
        // returns null too -- the actual pong timing shows up later via
        // getpeerinfo's "pingtime", which this project doesn't populate
        // for the same reason. Kept as a real, matching no-op rather
        // than removed, since RPC clients call it just to confirm
        // liveness of the RPC server itself.
        return "null";
    }

    /**
     * Matches real hsd's "setban" -- but only plain IPs, not CIDR/netmask
     * ranges (this project's PeerScorecard bans individual IPs, not
     * ranges; adding real netmask-range banning would be a genuinely
     * separate feature).
     */
    private String setBan(String params) throws RpcException {
        String ip     = parseStringParam(params, 0);
        String action = parseStringParam(params, 1);
        if (ip == null || action == null
                || !("add".equals(action) || "remove".equals(action))) {
            throw new RpcException(-1,
                    "setban \"ip\" \"add|remove\" (bantime) (absolute)");
        }
        if ("add".equals(action)) {
            PeerTable.get().banPeer(ip, "banned via RPC");
        } else {
            PeerTable.get().unbanPeer(ip);
        }
        return "null";
    }

    /**
     * Matches real hsd's listbanned shape. "banned_until" is computed as
     * a conventional 24-hour ban window from ban_created for shape
     * compatibility -- but note this project's actual ban enforcement
     * doesn't expire automatically the way real hsd's does; a ban here
     * stays in effect until process restart or an explicit "setban ...
     * remove"/clearbanned call, regardless of what banned_until shows.
     */
    private String listBanned() {
        List<PeerTable.Peer> banned = PeerTable.get().listBannedPeers();
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < banned.size(); i++) {
            if (i > 0) sb.append(",");
            PeerTable.Peer r = banned.get(i);
            long createdSec = r.banTime / 1000;
            sb.append("{")
                    .append("\"address\":\"").append(r.ip).append("\",")
                    .append("\"banned_until\":").append(createdSec + 86400).append(",")
                    .append("\"ban_created\":").append(createdSec).append(",")
                    .append("\"ban_reason\":\"").append(jsonEscape(
                            r.banReason != null ? r.banReason : "")).append("\"")
                    .append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    private String clearBanned() {
        PeerTable.get().clearAllBans();
        return "null";
    }

    /**
     * Matches real hsd's "getblockchaininfo". "softforks" is omitted
     * rather than faked -- this project doesn't track soft-fork
     * deployment status, and an empty/fake object would misrepresent
     * that as "no soft-forks defined" rather than "not tracked".
     */
    private String getBlockchainInfo() {
        int tip = db.getBlockTip();
        byte[] tipHeader = tip >= 0 ? db.getHeader(tip) : null;
        BigInteger work = tip >= 0 ? db.getChainwork(tip) : null;
        double progress = 0;
        byte[] g = db.getHeader(0);
        if (tipHeader != null && g != null) {
            double end = NodeClock.nowSec() - HeaderUtil.time(g) - 40 * 60;
            progress = end <= 0 ? 1 : Math.min(1.0, (HeaderUtil.time(tipHeader) - HeaderUtil.time(g)) / end);
        }
        String type = BlockProcessor.params.type;
        // softforks: this node applies the rule changes by height, it does not track BIP9 deployment state
        return "{"
                + "\"chain\":\"" + ("testnet".equals(type) ? "test" : type) + "\","
                + "\"blocks\":" + tip + ","
                + "\"headers\":" + tip + ","
                + "\"bestblockhash\":\"" + (tipHeader != null ? hex(HeaderUtil.hash(tipHeader)) : "") + "\","
                + "\"treeroot\":\"" + (tipHeader != null ? hex(HeaderUtil.treeRoot(tipHeader)) : "") + "\","
                + "\"difficulty\":" + (tipHeader != null ? number(toDifficulty(HeaderUtil.bits(tipHeader))) : "0") + ","
                + "\"mediantime\":" + (tip >= 0 ? computeMedianTime(tip) : 0) + ","
                + "\"verificationprogress\":" + number(progress) + ","
                + "\"chainwork\":\"" + chainwork64(work) + "\","
                + "\"pruned\":false,"
                + "\"softforks\":{},"
                + "\"deflationary\":" + (tip >= BlockProcessor.params.deflationHeight) + ","
                + "\"pruneheight\":null"
                + "}";
    }

    private String getDifficulty() {
        int tip = db.getHeaderTip();
        byte[] tipHeader = tip >= 0 ? db.getHeader(tip) : null;
        return String.valueOf(tipHeader != null ? toDifficulty(HeaderUtil.bits(tipHeader)) : 0);
    }

    static double difficultyOf(int bits) { return toDifficulty(bits); }

    /** JSON number text the way JS prints it: integers without a fraction, no NaN/Infinity. */
    static String number(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return "0";
        if (d == Math.rint(d) && Math.abs(d) < 1e15) return String.valueOf((long) d);
        return String.valueOf(d);
    }

    /** Matches real hsd's toDifficulty() exactly (lib/validator/rpc.js). */
    private static double toDifficulty(int bits) {
        int shift = (bits >>> 24) & 0xff;
        double diff = 0x0000ffff / (double) (bits & 0x00ffffff);
        while (shift < 29) { diff *= 256.0; shift++; }
        while (shift > 29) { diff /= 256.0; shift--; }
        return diff;
    }

    private String getNames() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (ChainDB.NameEntry e : db.getAllNames()) {
            if (!first) sb.append(",");
            first = false;
            sb.append(nameEntryToJson(e, e.name));
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Matches real hsd's validateaddress shape. isspendable is always
     * true for any address that decodes successfully -- this project
     * doesn't implement hsd's "unspendable" address concept (a rare,
     * specific marker case), so rather than guess at that check, every
     * successfully-decoded address is treated as spendable, which is
     * correct for the overwhelming majority of real addresses.
     */
    // ── Mining ────────────────────────────────────────────────────────────────

    /**
     * getblocktemplate {"address":"hs1q...", "coinbaseflags":"text"} (or just the address
     * string). Returns a coinbase-only template extending our current tip,
     * in hsd/BIP22 style field names, plus the pieces a miner needs to build the
     * header (treeroot, reservedroot, merkleroot, witnessroot, bits, target)
     * and the finished coinbase transaction.
     */
    /**
     * getblocktemplate, following hsd's rpc.js: optional request object ({mode, data, capabilities, rules,
     * maxversion, longpollid}); "proposal" mode judges a block on everything but proof of work; the template is
     * the shared one getwork uses (reward address from {@code miner.address}). Extensions this node keeps:
     * a reward {@code address} in the request (builds a private template for that address), and the
     * coinbase transaction and ready-made 236-byte header are always included.
     */
    private String getBlockTemplate(String params) throws RpcException {
        if (chainSync == null) throw new RpcException(-1, "Node not ready");
        String addr = null;
        String flags = null;
        String mode = "template";
        String proposalData = null;
        String longpollId = null;
        List<String> pl = parseParamList(params);
        if (pl.size() > 1) throw new RpcException(-1, "getblocktemplate ( \"jsonrequestobject\" )");
        if (!pl.isEmpty()) {
            String f = pl.get(0).trim();
            if (f.startsWith("{")) {
                java.util.LinkedHashMap<String, String> o = parseObjectParam(params, 0);
                addr = unquote(o.get("address"));
                flags = unquote(o.get("coinbaseflags"));
                if (o.get("mode") != null) mode = unquote(o.get("mode"));
                proposalData = unquote(o.get("data"));
                longpollId = unquote(o.get("longpollid"));
            } else {
                addr = unquote(f);
            }
        }
        if (!mode.equals("template") && !mode.equals("proposal")) throw new RpcException(-8, "Invalid mode.");

        if (mode.equals("proposal")) {
            if (proposalData == null) throw new RpcException(-3, "Missing data parameter.");
            byte[] raw;
            try { raw = fromHex(proposalData); } catch (Exception e) { throw new RpcException(-22, "Block decode failed"); }
            String r = BlockTemplates.checkBlock(db, mempool, raw, NodeClock.nowSec(),
                    chainSync.getPowParams(), false);
            return r == null ? "null" : "\"" + escape(r) + "\"";
        }

        int tipH = db.getBlockTip();
        if (tipH < 0 || db.getHeaderTip() != tipH)
            throw new RpcException(-10, "Node is still syncing");
        byte[] tipHeader = db.getHeader(tipH);
        if (tipHeader == null) throw new RpcException(-10, "Node is still syncing");
        long now = NodeClock.nowSec();
        if (now - HeaderUtil.time(tipHeader) > 6 * 3600)
            throw new RpcException(-10, "Chain tip is more than 6 hours old -- node is not caught up");
        if (chainSync.getConnectedPeerCount() == 0)
            throw new RpcException(-9, "Node is not connected to any peers");

        if (longpollId != null && !longpollId.isEmpty()) {
            if (longpollId.length() != 72) throw new RpcException(-8, "Invalid longpoll ID.");
            byte[] watched;
            try {
                watched = fromHex(longpollId.substring(0, 64));
                Long.parseLong(longpollId.substring(64), 16);
            } catch (Exception e) { throw new RpcException(-8, "Invalid longpoll ID."); }
            if (Arrays.equals(watched, HeaderUtil.hash(tipHeader))) mining().awaitChange(watched);
            tipH = db.getBlockTip();
            tipHeader = db.getHeader(tipH);
            now = NodeClock.nowSec();
        }

        BlockTemplates.Template t;
        if (addr != null && !addr.isEmpty()) {
            Object[] a = MiningService.decodeAddress(addr);
            byte[] flagBytes = (flags != null ? flags : config.getMinerCoinbaseFlags()).getBytes(StandardCharsets.UTF_8);
            if (flagBytes.length > 100) throw new RpcException(-8, "coinbaseflags too long");
            try {
                t = BlockTemplates.build(db, mempool, (int) a[0], (byte[]) a[1], flagBytes, now, chainSync.getPowParams());
            } catch (Exception e) {
                throw new RpcException(-1, "Could not build template: " + e.getMessage());
            }
        } else {
            t = mining().updateWork();
        }
        byte[] target = MiningService.targetBytes(t.bits);

        StringBuilder txs = new StringBuilder("[");
        for (int i = 0; i < t.txs.size(); i++) {
            BlockTemplates.Included it = t.txs.get(i);
            if (i > 0) txs.append(',');
            txs.append("{\"data\":\"").append(hex(it.raw)).append("\",\"txid\":\"").append(hex(it.txid))
                    .append("\",\"hash\":\"").append(hex(it.wtxid)).append("\",\"depends\":").append(it.depends.toString().replace(" ", ""))
                    .append(",\"fee\":").append(it.fee).append(",\"sigops\":0,\"weight\":").append(it.weight).append('}');
        }
        txs.append(']');
        String flagsHex = hex((flags != null ? flags : config.getMinerCoinbaseFlags()).getBytes(StandardCharsets.UTF_8));
        int pooled = mempool == null ? 0 : mempool.size();

        return "{"
                + "\"capabilities\":[\"proposal\"],"
                + "\"mutable\":[\"time\",\"transactions\",\"prevblock\"],"
                + "\"version\":" + t.version + ","
                + "\"rules\":[],"
                + "\"vbavailable\":{},"
                + "\"vbrequired\":0,"
                + "\"height\":" + t.height + ","
                + "\"previousblockhash\":\"" + hex(t.prevHash) + "\","
                + "\"treeroot\":\"" + hex(t.treeRoot) + "\","
                + "\"reservedroot\":\"" + hex(t.reservedRoot) + "\","
                + "\"merkleroot\":\"" + hex(t.merkleRoot) + "\","
                + "\"witnessroot\":\"" + hex(t.witnessRoot) + "\","
                + "\"mask\":\"" + hex(new byte[32]) + "\","
                + "\"target\":\"" + hex(target) + "\","
                + "\"bits\":\"" + String.format("%08x", t.bits) + "\","
                + "\"noncerange\":\"00000000ffffffff\","
                + "\"curtime\":" + t.curTime + ","
                + "\"mintime\":" + t.minTime + ","
                + "\"maxtime\":" + (t.curTime + 7200) + ","
                + "\"expires\":" + (t.curTime + 7200) + ","
                + "\"sigoplimit\":80000,"
                + "\"sizelimit\":" + BlockTemplates.MAX_BLOCK_SIZE + ","
                + "\"weightlimit\":" + BlockTemplates.MAX_BLOCK_WEIGHT + ","
                + "\"longpollid\":\"" + hex(t.prevHash) + String.format("%08x", pooled) + "\","
                + "\"submitold\":false,"
                + "\"coinbaseaux\":{\"flags\":\"" + flagsHex + "\"},"
                + "\"coinbasevalue\":" + t.coinbaseValue + ","
                + "\"coinbasetxn\":{\"data\":\"" + hex(t.coinbase.raw) + "\","
                + "\"txid\":\"" + hex(t.coinbase.txid) + "\","
                + "\"hash\":\"" + hex(t.coinbase.witnessHash) + "\","
                + "\"depends\":[],\"fee\":0,\"sigops\":0,\"weight\":0},"
                + "\"claims\":[],\"airdrops\":[],"
                + "\"transactions\":" + txs + ","
                + "\"header\":\"" + hex(t.header(0, t.curTime, new byte[24], new byte[32])) + "\""
                + "}";
    }

    private String submitBlock(String params) throws RpcException {
        if (chainSync == null) throw new RpcException(-1, "Node not ready");
        String hexBlock = parseStringParam(params, 0);
        if (hexBlock == null || hexBlock.isEmpty())
            throw new RpcException(-22, "submitblock \"hexdata\"");
        byte[] raw;
        try {
            raw = fromHex(hexBlock);
        } catch (Exception e) {
            throw new RpcException(-22, "Block decode failed");
        }
        String result = chainSync.submitBlock(raw);
        return result == null ? "null" : "\"" + escape(result) + "\"";
    }

    private static String unquote(String v) {
        if (v == null) return null;
        v = v.trim();
        if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) return v.substring(1, v.length() - 1);
        return v;
    }

    private String validateAddress(String params) throws RpcException {
        String str = parseStringParam(params, 0);
        if (str == null) throw new RpcException(-1, "validateaddress \"address\"");
        try {
            Object[] decoded = Bech32.decode(str);
            String hrp = (String) decoded[0];
            int version = (int) decoded[1];
            byte[] hash = (byte[]) decoded[2];
            boolean isScripthash = version == 0 && hash.length == 32;
            return "{"
                    + "\"isvalid\":true,"
                    + "\"address\":\"" + str + "\","
                    + "\"isscript\":" + isScripthash + ","
                    + "\"isspendable\":true,"
                    + "\"witness_version\":" + version + ","
                    + "\"witness_program\":\"" + hex(hash) + "\""
                    + "}";
        } catch (Exception e) {
            return "{\"isvalid\":false}";
        }
    }

    /**
     * Matches real hsd's gettxoutproof. Requires an explicit blockhash
     * for multi-txid proofs (matching hsd's own behavior when args.length
     * is 2). For a single txid with no blockhash, falls back to the same
     * approach real hsd itself uses when it has no maintained tx index:
     * check whether txid:0 is a currently-unspent UTXO, and use its
     * stored height. If that fails too (already spent, or genuinely not
     * found), the caller needs to supply the blockhash explicitly --
     * this project doesn't maintain a full historical tx->block index.
     */
    private String getTxOutProof(String params) throws RpcException {
        List<String> txids = parseStringArrayParam(params, 0);
        if (txids == null || txids.isEmpty())
            throw new RpcException(-8, "Invalid TXIDs.");

        String blockHash = parseStringParam(params, 1);
        byte[] rawBlock;
        int height;

        if (blockHash != null) {
            height = resolveHeight(blockHash);
            rawBlock = db.getBlock(height);
        } else {
            if (txids.size() > 1) throw new RpcException(-8,
                    "Please specify a block hash to use with multiple txids.");
            ChainDB.UtxoEntry utxo = db.getUtxo(txids.get(0), 0);
            if (utxo == null) throw new RpcException(-5,
                    "Transaction not yet in block, or already spent -- specify a block hash.");
            height = utxo.height();
            rawBlock = db.getBlock(height);
        }
        if (rawBlock == null) throw new RpcException(-5, "Block not found.");

        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
        List<byte[]> leaves = new ArrayList<>();
        for (TxParser.ParsedTx tx : txs) {
            leaves.add(Blake2b.hash256(Arrays.copyOf(tx.raw, tx.baseSize)));
        }

        boolean[] matches = new boolean[leaves.size()];
        for (String txid : txids) {
            boolean matched = false;
            for (int i = 0; i < txs.size(); i++) {
                if (TxParser.computeTxid(txs.get(i).raw).equals(txid)) {
                    matches[i] = true;
                    matched = true;
                    break;
                }
            }
            if (!matched) throw new RpcException(-5, "Block does not contain all txids.");
        }

        MerkleProof.BuiltProof proof = MerkleProof.buildProof(leaves, matches);
        byte[] header = Arrays.copyOf(rawBlock, 236);
        byte[] serialized = MerkleProof.serialize(header, proof);
        return "\"" + hex(serialized) + "\"";
    }

    /**
     * Matches real hsd's verifytxoutproof: returns the matched txids if
     * the proof is valid AND its reconstructed root matches a real,
     * known block's header -- an empty array otherwise (not an error;
     * an invalid or unrecognized proof isn't a request failure, it's
     * just a "no" answer, matching real hsd's own behavior here).
     */
    private String verifyTxOutProof(String params) throws RpcException {
        String proofHex = parseStringParam(params, 0);
        if (proofHex == null) throw new RpcException(-22, "Invalid hex string.");
        byte[] data = fromHex(proofHex);
        if (data.length < 240) return "[]";

        MerkleProof.ParsedProof parsed = MerkleProof.deserialize(data);
        MerkleProof.ExtractedTree tree = MerkleProof.extractTree(
                parsed.totalTX, parsed.hashes, parsed.flags);
        if (tree.failed) return "[]";

        byte[] claimedRoot = HeaderUtil.merkleRoot(parsed.header);
        if (!Arrays.equals(tree.root, claimedRoot)) return "[]";

        // Confirm this header is a real, known block in our chain --
        // a structurally valid proof over a header we've never seen
        // proves nothing.
        // FIX: used to hex-encode just to call the String-taking
        // overload, which immediately decoded it right back -- now
        // calls the direct byte[] overload instead.
        int height = db.getHeightByHash(HeaderUtil.hash(parsed.header));
        if (height < 0) return "[]";

        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < tree.matches.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(hex(tree.matches.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    private String getMemoryInfo() {
        Runtime rt = Runtime.getRuntime();
        long total = rt.totalMemory();
        long free = rt.freeMemory();
        long used = total - free;
        long max = rt.maxMemory(); // FIX: the actual -Xmx ceiling -- previously missing
        // entirely, so there was no way to see "used vs the real limit",
        // only "used vs currently-allocated" (which itself grows toward
        // the ceiling over time and isn't the same thing).
        return "{"
                + "\"total\":" + (total / 1_048_576) + ","
                + "\"jsHeap\":" + (used / 1_048_576) + ","
                + "\"jsHeapTotal\":" + (total / 1_048_576) + ","
                + "\"jsHeapMax\":" + (max / 1_048_576) + ","
                + "\"nativeHeap\":0,"
                + "\"external\":0"
                + "}";
    }

    private String getNetTotals() {
        return "{"
                + "\"totalbytesrecv\":" + ChainSync.getTotalBytesRecv() + ","
                + "\"totalbytessent\":" + ChainSync.getTotalBytesSent() + ","
                + "\"timemillis\":" + System.currentTimeMillis()
                + "}";
    }

    /**
     * Matches real hsd's pruneblockchain -- but this project never
     * implements pruning at all (it keeps every block permanently), so
     * this is an honest no-op that succeeds without actually discarding
     * anything, rather than silently pretending to prune.
     */
    private String pruneBlockchain() {
        return "null";
    }

    /**
     * addnode/disconnectnode/getaddednodeinfo map onto this project's
     * SeedDatabase-based peer tracking as closely as the underlying
     * model allows. This project doesn't hold persistent, long-lived
     * outbound connections the way real hsd does (connections are
     * opened per sync batch and closed), so "add" registers the peer
     * for future connection attempts rather than connecting immediately,
     * and "disconnectnode" has no persistent connection to actually
     * close -- it's accepted but is a no-op beyond that, which is an
     * honest limitation given this project's connection model, not a
     * missing feature.
     * <p>
     * Brontide-only: accepts the same "key@host:port" format real hsd
     * uses everywhere else a peer is identified by address (its own
     * getinfo output, DNS seed entries, ADDR gossip) -- e.g.
     *   addnode "aonetsezqp4m52w4jpfq2gv3dggy2wqfwqtkfjyttgdidbvhgp5as@165.22.151.242:44806" add
     * Previously this always passed an empty key to addDiscovered(),
     * which meant an added peer could never actually appear in
     * PeerDiscovery.getCandidates() at all (that requires a real key) --
     * a real, pre-existing bug, not something this cleanup introduces.
     * A bare "host[:port]" with no key is still accepted without error
     * (matching real hsd's own tolerance of keyless addnode targets),
     * but -- consistent with the rest of this project now -- it's
     * registered without a key and so never becomes a connectable
     * candidate; only a properly-keyed address actually results in a
     * peer we'll ever try to reach.
     */
    private String addNode(String params) throws RpcException {
        String addr = parseStringParam(params, 0);
        String cmd  = parseStringParam(params, 1);
        if (addr == null || cmd == null) throw new RpcException(-1,
                "addnode \"validator\" \"add|remove|onetry\"");
        if ("remove".equals(cmd)) {
            // Unpins the peer (the row stays in the peer table as an ordinary peer).
            String h = addr.contains("@") ? addr.substring(addr.indexOf('@') + 1) : addr;
            PeerTable.get().unpin(h.split(":")[0]);
            return "null";
        }

        String key = "";
        String hostPart = addr;
        int at = addr.indexOf('@');
        if (at >= 0) {
            String keyStr = addr.substring(0, at);
            hostPart = addr.substring(at + 1);
            byte[] keyBytes = NodeIdentity.base32Decode(keyStr);
            if (keyBytes.length == 33) {
                key = keyStr;
            }
            // else: malformed key -- fall through and register keyless,
            // same as a bare host with no "@" at all, rather than
            // rejecting the whole call over a bad key.
        }

        String[] parts = hostPart.split(":");
        String ip = parts[0];
        // Keyed address: Brontide, default 44806. Bare host (no key): a
        // cleartext peer, default 12038 -- the only keyless port the node
        // will ever dial (see PeerTable.getCandidates()).
        int port = parts.length > 1 ? Integer.parseInt(parts[1])
                : (key.isEmpty() ? PeerTable.PLAIN_PORT : 44806);

        PeerTable.get().addDiscovered(key, ip, port, "rpc-addnode");
        // "add" = standing connection (pinned); "onetry" only registers the address.
        if ("add".equals(cmd)) PeerTable.get().pin(ip);
        return "null";
    }

    private String disconnectNode(String params) throws RpcException {
        String addr = parseStringParam(params, 0);
        if (addr == null) throw new RpcException(-1, "disconnectnode \"validator\"");
        return "null";
    }

    private String getAddedNodeInfo(String params) throws RpcException {
        String addr = parseStringParam(params, 0);
        if (addr == null) throw new RpcException(-1, "getaddednodeinfo \"validator\"");
        String ip = addr.split(":")[0];
        // isDiscovered() alone now covers both seeds and gossiped/inbound
        // peers -- the unified table tracks everything it knows under one
        // membership check (previously this needed a separate SeedDatabase
        // lookup too).
        boolean known = PeerTable.get().isDiscovered(ip);
        if (!known) return "[]";
        return "[{"
                + "\"addednode\":\"" + addr + "\","
                + "\"connected\":false,"
                + "\"addresses\":[]"
                + "}]";
    }

    /**
     * Matches real hsd's prioritisetransaction -- but this project's
     * mempool doesn't implement fee/priority bumping at all (there's no
     * miner to influence), so this always succeeds without doing
     * anything, an honest no-op rather than a real reordering.
     */
    private String prioritiseTransaction(String params) throws RpcException {
        String txid = parseStringParam(params, 0);
        if (txid == null) throw new RpcException(-1,
                "prioritisetransaction \"txid\" priority_delta fee_delta");
        return "true";
    }

    /**
     * Walks the mempool's actual input/output graph to find real
     * in-mempool ancestors (transactions this one spends from) or
     * descendants (transactions that spend from this one). "priority"
     * fields are always 0 -- this project doesn't track coin age, a
     * legacy concept with little modern relevance anyway.
     */
    private String getMempoolAncestors(String params) throws RpcException {
        String txid = parseStringParam(params, 0);
        boolean verbose = parseBoolParam(params, 1, false);
        if (mempool == null || mempool.getEntry(txid) == null)
            throw new RpcException(-5, "Transaction not in mempool");
        Set<String> ancestors = new LinkedHashSet<>();
        collectAncestors(txid, ancestors);
        return mempoolDepsToJson(ancestors, verbose);
    }

    private String getMempoolDescendants(String params) throws RpcException {
        String txid = parseStringParam(params, 0);
        boolean verbose = parseBoolParam(params, 1, false);
        if (mempool == null || mempool.getEntry(txid) == null)
            throw new RpcException(-5, "Transaction not in mempool");
        Set<String> descendants = new LinkedHashSet<>();
        collectDescendants(txid, descendants);
        return mempoolDepsToJson(descendants, verbose);
    }

    private void collectAncestors(String txid, Set<String> found) {
        Mempool.MempoolEntry entry = mempool.getEntry(txid);
        if (entry == null) return;
        TxParser.ParsedTx tx = TxParser.parse(entry.raw);
        if (tx == null) return;
        for (TxParser.Input in : tx.inputs) {
            if (mempool.getEntry(in.prevTxid) != null && found.add(in.prevTxid)) {
                collectAncestors(in.prevTxid, found);
            }
        }
    }

    private void collectDescendants(String txid, Set<String> found) {
        for (Mempool.MempoolEntry entry : mempool.getAll()) {
            if (found.contains(entry.txid)) continue;
            TxParser.ParsedTx tx = TxParser.parse(entry.raw);
            if (tx == null) continue;
            for (TxParser.Input in : tx.inputs) {
                if (in.prevTxid.equals(txid)) {
                    found.add(entry.txid);
                    collectDescendants(entry.txid, found);
                    break;
                }
            }
        }
    }

    private String mempoolDepsToJson(Set<String> txids, boolean verbose) {
        if (!verbose) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (String t : txids) {
                if (!first) sb.append(",");
                sb.append("\"").append(t).append("\"");
                first = false;
            }
            return sb.append("]").toString();
        }
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String t : txids) {
            if (!first) sb.append(",");
            String entry = mempool.getEntryJson(t);
            sb.append(entry != null ? entry : "null");
            first = false;
        }
        return sb.append("]").toString();
    }

    /**
     * Only recognizes the standard witness-pubkeyhash script pattern
     * (OP_DUP OP_BLAKE160 <20-byte-push> OP_EQUALVERIFY OP_CHECKSIG) --
     * the only pattern this project can meaningfully name/type, matching
     * TxVerify's own P2PKH script builder. Anything else returns a
     * minimal, honest "unrecognized" response rather than a guessed-at
     * disassembly.
     */
    private String decodeScript(String params) throws RpcException {
        String hex = parseStringParam(params, 0);
        if (hex == null) throw new RpcException(-22, "Missing script");
        byte[] script = fromHex(hex);
        if (script.length == 25 && (script[0] & 0xFF) == 0x76 && (script[1] & 0xFF) == 0xc0
                && (script[2] & 0xFF) == 0x14 && (script[23] & 0xFF) == 0x88 && (script[24] & 0xFF) == 0xac) {
            byte[] hash20 = Arrays.copyOfRange(script, 3, 23);
            String p2sh = Bech32.encode(Bech32.hrpForNetwork(config.getNetwork()), 0,
                    HeaderUtil.sha3_256(script));
            return "{"
                    + "\"asm\":\"OP_DUP OP_BLAKE160 " + hex(hash20) + " OP_EQUALVERIFY OP_CHECKSIG\","
                    + "\"type\":\"PUBKEYHASH\","
                    + "\"reqSigs\":1,"
                    + "\"p2sh\":\"" + p2sh + "\""
                    + "}";
        }
        return "{\"asm\":\"" + hex(script) + "\",\"type\":\"NONSTANDARD\",\"reqSigs\":0}";
    }

    /**
     * Builds a standard M-of-N multisig script (OP_m <pubkeys...> OP_n
     * OP_CHECKMULTISIG) and its scripthash address. Pubkeys are sorted
     * numerically by their own bytes first -- matching real hsd/bitcoin
     * convention for deterministic multisig scripts regardless of the
     * order keys were supplied in.
     */
    private String createMultisig(String params) throws RpcException {
        int nrequired = parseIntParam(params, 0);
        List<String> pubkeyHex = parseStringArrayParam(params, 1);
        if (pubkeyHex == null || pubkeyHex.isEmpty())
            throw new RpcException(-8, "Invalid public keys");
        if (nrequired < 1 || nrequired > pubkeyHex.size())
            throw new RpcException(-8, "Invalid number of required signatures");

        List<byte[]> pubkeys = new ArrayList<>();
        for (String h : pubkeyHex) pubkeys.add(fromHex(h));
        pubkeys.sort((a, b) -> {
            for (int i = 0; i < Math.min(a.length, b.length); i++) {
                int cmp = Integer.compare(a[i] & 0xFF, b[i] & 0xFF);
                if (cmp != 0) return cmp;
            }
            return Integer.compare(a.length, b.length);
        });

        int n = pubkeys.size();
        int size = 1 + n * 34 + 1 + 1; // OP_m + n*(push+33) + OP_n + OP_CHECKMULTISIG
        byte[] script = new byte[size];
        int pos = 0;
        script[pos++] = (byte) (0x50 + nrequired); // OP_1..OP_16 = 0x51..0x60; OP_m via 0x50+m
        for (byte[] pk : pubkeys) {
            script[pos++] = 0x21; // push 33 bytes
            System.arraycopy(pk, 0, script, pos, 33);
            pos += 33;
        }
        script[pos++] = (byte) (0x50 + n);
        script[pos++] = (byte) 0xae; // OP_CHECKMULTISIG

        String address = Bech32.encode(Bech32.hrpForNetwork(config.getNetwork()), 0,
                HeaderUtil.sha3_256(script));
        return "{"
                + "\"address\":\"" + address + "\","
                + "\"redeemScript\":\"" + hex(script) + "\""
                + "}";
    }

    /**
     * Matches real hsd's createrawtransaction shape: builds a complete
     * but genuinely UNSIGNED transaction from given input outpoints and
     * address:amount outputs -- no private keys or signing involved at
     * all, which is exactly why this fits on the validator side despite
     * "creating a transaction" sounding wallet-like. A real wallet (or
     * anything else holding the right keys) would sign the result
     * separately before broadcasting it.
     */
    private String createRawTransaction(String params) throws RpcException {
        List<String> inputSpecs = parseStringArrayParam(params, 0);
        java.util.LinkedHashMap<String, String> outputSpecs = parseObjectParam(params, 1);
        int locktime = 0;
        List<String> rawParamList = parseParamList(params);
        if (rawParamList.size() > 2) {
            try { locktime = Integer.parseInt(rawParamList.get(2).trim()); }
            catch (NumberFormatException ignored) {}
        }

        if (inputSpecs == null || outputSpecs.isEmpty())
            throw new RpcException(-22, "Invalid parameters (inputs and sendTo).");

        List<TxParser.Input> inputs = new ArrayList<>();
        for (String spec : inputSpecs) {
            java.util.LinkedHashMap<String, String> fields = parseObjectParam("[" + spec + "]", 0);
            String txidRaw = fields.get("txid");
            String voutRaw = fields.get("vout");
            if (txidRaw == null || voutRaw == null)
                throw new RpcException(-22, "Invalid outpoint.");
            String txid = txidRaw.replace("\"", "");
            TxParser.Input in = new TxParser.Input();
            in.prevHash = HexUtil.decode(txid); // Handshake txids are not byte-reversed
            in.prevTxid = txid;
            in.prevIndex = Integer.parseInt(voutRaw.trim());
            String seqRaw = fields.get("sequence");
            in.sequence = seqRaw != null ? (int) Long.parseLong(seqRaw.trim()) : 0xffffffff;
            if (locktime != 0) in.sequence -= 1;
            inputs.add(in);
        }

        List<TxParser.Output> outputs = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (var entry : outputSpecs.entrySet()) {
            String key = entry.getKey();
            String rawValue = entry.getValue();
            TxParser.Output out = new TxParser.Output();
            out.covenant = new TxParser.Covenant();
            out.covenant.type = TxParser.COV_NONE;

            if ("data".equals(key)) {
                String hex = rawValue.replace("\"", "");
                out.value = 0;
                out.addrVersion = 31; // nulldata, matching real hsd's Address.fromNulldata()
                out.addrHash = fromHex(hex);
            } else {
                if (!seen.add(key)) throw new RpcException(-8, "Duplicate address");
                Object[] decoded;
                try {
                    decoded = Bech32.decode(key);
                } catch (Exception e) {
                    throw new RpcException(-5, "Invalid address: " + key);
                }
                out.addrVersion = (int) decoded[1];
                out.addrHash = (byte[]) decoded[2];
                double amount = Double.parseDouble(rawValue.trim());
                out.value = Math.round(amount * 1_000_000.0);
            }
            outputs.add(out);
        }

        byte[] raw = TxVerify.serializeUnsignedTx(0, inputs, outputs, locktime);
        return "\"" + hex(raw) + "\"";
    }

    /** Reverses a display-format (byte-reversed) hex txid string back
     *  into raw, wire-order bytes. */
    private static byte[] reverseHex(String hex) {
        byte[] b = fromHex(hex);
        byte[] reversed = new byte[b.length];
        for (int i = 0; i < b.length; i++) reversed[i] = b[b.length - 1 - i];
        return reversed;
    }

    /**
     * Matches real hsd's verifyblock: validates a standalone raw block
     * without connecting it to the chain (no state changes, no DB
     * writes). Checks the same merkle-root and proof-of-work rules
     * BlockProcessor/header-sync already enforce, plus signature
     * verification wherever the referenced UTXO happens to already
     * exist in this validator's own chain state -- honestly weaker than real
     * hsd's full contextual validation (difficulty/timestamp rules
     * against actual chain position, etc.), since a standalone call like
     * this doesn't know where in the chain the block is meant to
     * attach. Returns null on success, or a short reason string on the
     * first failure found -- matching real hsd's own return shape.
     */
    private String verifyBlock(String params) throws RpcException {
        String hex = parseStringParam(params, 0);
        if (hex == null) throw new RpcException(-22, "Invalid block hex.");
        byte[] rawBlock = fromHex(hex);
        if (rawBlock.length < 236) return "\"bad-header-size\"";

        byte[] header = Arrays.copyOf(rawBlock, 236);
        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);

        List<byte[]> txids = new ArrayList<>();
        for (TxParser.ParsedTx tx : txs) {
            txids.add(Blake2b.hash256(Arrays.copyOf(tx.raw, tx.baseSize)));
        }
        byte[] claimedRoot = HeaderUtil.merkleRoot(header);
        if (!MerkleUtil.verify(txids, claimedRoot)) {
            return "\"bad-txnmrklroot\"";
        }

        if (!HeaderUtil.checkPOW(header)) {
            return "\"high-hash\"";
        }

        for (TxParser.ParsedTx tx : txs) {
            if (!tx.inputs.isEmpty() && !tx.inputs.get(0).isCoinbase()) {
                for (int i = 0; i < tx.inputs.size(); i++) {
                    TxParser.Input input = tx.inputs.get(i);
                    ChainDB.UtxoEntry spentUtxo = db.getUtxo(input.prevTxid, input.prevIndex);
                    if (spentUtxo == null || spentUtxo.addrHash().length != 20) continue;
                    if (!TxVerify.verifyInput(tx, i, spentUtxo.addrHash(), spentUtxo.value())) {
                        return "\"mandatory-script-verify-flag-failed\"";
                    }
                }
            }
        }

        return "null";
    }

    /**
     * Matches real hsd's estimatefee/estimatesmartfee shape, but NOT its
     * algorithm -- real hsd maintains a dedicated fee-estimator tracking
     * historical, per-confirmation-target statistics across many
     * confirmed blocks (and, tellingly, throws "Fee estimation not
     * available" if that component isn't initialized, rather than
     * fabricating a number -- a real, honest precedent worth following
     * here too, just with a different fallback: this project doesn't
     * have that historical estimator at all, so instead of either
     * refusing outright or pretending to replicate hsd's real algorithm,
     * this returns the median fee-rate currently observed across the
     * live mempool -- clearly a different, much simpler method, and
     * explicitly documented as such rather than presented as
     * equivalent. It also doesn't vary by the requested confirmation
     * target (nblocks) at all, unlike real hsd's, since there's no
     * historical, per-target data to vary it by.
     */
    private String estimateFee(String params) {
        double medianRate = computeMedianMempoolFeeRate();
        if (medianRate < 0) return "-1";
        return String.valueOf(medianRate / 1_000_000.0); // dollarydoos/kB -> HNS/kB
    }

    private String estimateSmartFee(String params) {
        int blocks = parseIntParamOrDefault(params, 0, 1);
        double medianRate = computeMedianMempoolFeeRate();
        double feeOrMinusOne = medianRate < 0 ? -1 : medianRate / 1_000_000.0;
        return "{\"fee\":" + feeOrMinusOne + ",\"blocks\":" + blocks + "}";
    }

    /** Median fee-rate (dollarydoos per kB) across everything currently
     *  in the mempool, or -1 if the mempool is empty. */
    private double computeMedianMempoolFeeRate() {
        if (mempool == null) return -1;
        List<Double> rates = new ArrayList<>();
        for (Mempool.MempoolEntry e : mempool.getAll()) {
            rates.add(e.fee / (e.size / 1000.0));
        }
        if (rates.isEmpty()) return -1;
        Collections.sort(rates);
        return rates.get(rates.size() / 2);
    }

    private static int parseIntParamOrDefault(String params, int index, int def) {
        try {
            return parseIntParam(params, index);
        } catch (Exception e) {
            return def;
        }
    }

    private String help() {
        // Generated from RPC_METHODS, sorted for stable, readable
        // output -- not a separately hand-maintained string anymore.
        String[] sorted = RPC_METHODS.clone();
        java.util.Arrays.sort(sorted);
        return "\"Available methods: " + String.join(", ", sorted) + "\"";
    }

    private String getBlockByHeight(String params) throws RpcException {
        int height = parseIntParam(params, 0);
        byte[] rawBlock = db.getBlock(height);
        if (rawBlock == null) throw new RpcException(-5,
                "Block not found at height " + height);
        boolean verbose = parseBoolParam(params, 1, true);
        if (!verbose) return "\"" + hex(rawBlock) + "\"";
        return blockToJson(rawBlock, height, parseBoolParam(params, 2, false));
    }

    /**
     * Matches real hsd's getchaintips -- but since this project doesn't
     * track competing forks at all (only the single active chain), this
     * always reports exactly one tip, status "active". A real
     * multi-chain-tips view would need fork-tracking this project simply
     * doesn't have.
     */
    private String getChainTips() {
        int tip = db.getHeaderTip();
        if (tip < 0) return "[]";
        byte[] header = db.getHeader(tip);
        return "[{"
                + "\"height\":" + tip + ","
                + "\"hash\":\"" + hex(HeaderUtil.hash(header)) + "\","
                + "\"branchlen\":0,"
                + "\"status\":\"active\""
                + "}]";
    }

    private String getMempoolInfo() {
        if (mempool == null) return "{\"size\":0,\"bytes\":0,\"usage\":0,\"maxmempool\":0,\"mempoolminfee\":0}";
        return "{"
                + "\"size\":" + mempool.size() + ","
                + "\"bytes\":" + mempool.getTotalBytes() + ","
                + "\"usage\":" + mempool.getTotalBytes() + ","
                + "\"maxmempool\":" + mempool.getMaxSize() + ","
                + "\"mempoolminfee\":" + (mempool.getMinRelayFee() / 1_000_000.0)
                + "}";
    }

    /**
     * Matches real hsd's gettxoutsetinfo shape. bytes_serialized and
     * hash_serialized are always 0, matching real hsd itself (it doesn't
     * actually compute these either -- they're vestigial fields in its
     * own response). "transactions" is also 0 here, but for a different,
     * more honest reason: unlike hsd, this project doesn't track a
     * running total transaction count anywhere (UTXOs get removed when
     * spent, so counting the UTXO set itself wouldn't give the right
     * number either) -- 0 reflects a real gap, not a vestigial field.
     */
    private String getTxOutSetInfo() {
        int tip = db.getHeaderTip();
        byte[] header = tip >= 0 ? db.getHeader(tip) : null;
        return "{"
                + "\"height\":" + db.getBlockTip() + ","
                + "\"bestblock\":\"" + (header != null ? hex(HeaderUtil.hash(header)) : "") + "\","
                + "\"transactions\":0,"
                + "\"txouts\":" + db.getUtxoCount() + ","
                + "\"bytes_serialized\":0,"
                + "\"hash_serialized\":0,"
                + "\"total_amount\":" + (db.getTotalUtxoValue() / 1_000_000.0)
                + "}";
    }


    private String stopNode() {
        System.out.println("[RPC] Stop requested via RPC.");
        new Thread(() -> {
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            System.exit(0);
        }).start();
        return "\"Node stopping...\"";
    }

    // ── JSON serialization helpers ────────────────────────────────────────────

    /** Median of up to the last 11 blocks' timestamps ending at height,
     *  matching standard Bitcoin-style "mediantime" convention. */
    private long computeMedianTime(int height) {
        List<Long> times = new ArrayList<>();
        for (int h = height; h > height - 11 && h >= 0; h--) {
            byte[] header = db.getHeader(h);
            if (header == null) break;
            times.add(HeaderUtil.time(header));
        }
        if (times.isEmpty()) return 0;
        Collections.sort(times);
        return times.get(times.size() / 2);
    }

    private String getNextBlockHashOrNull(int height) {
        int tip = db.getHeaderTip();
        if (height >= tip) return "null";
        byte[] next = db.getHeader(height + 1);
        return next != null ? "\"" + hex(HeaderUtil.hash(next)) + "\"" : "null";
    }

    private int getConfirmations(int height) {
        int tip = db.getBlockTip();
        return tip >= height ? (tip - height + 1) : -1;
    }

    /**
     * Matches real hsd's getblockheader shape exactly -- confirmed field
     * for field against the official RPC documentation, not the REST
     * API's similarly-named but differently-shaped response (which uses
     * camelCase and includes nonce/extraNonce; the RPC version below
     * uses lowercase and omits them entirely -- a real, confirmed
     * difference, not an oversight on this project's part).
     */
    private static String hex32(long v) { return String.format("%08x", v & 0xFFFFFFFFL); }

    private static String chainwork64(BigInteger w) {
        String h = w == null ? "0" : w.toString(16);
        return "0".repeat(Math.max(0, 64 - h.length())) + h;
    }

    /** hsd's Amount.coin(value, true): a plain number in HNS with up to 6 decimals, no trailing zeros. */
    static String coinAmount(long dollarydoos) {
        java.math.BigDecimal d = java.math.BigDecimal.valueOf(dollarydoos, 6);
        return d.signum() == 0 ? "0" : d.stripTrailingZeros().toPlainString();
    }

    private String addrJson(int version, byte[] hash) {
        return "{\"version\":" + version + ",\"hash\":\"" + hex(hash) + "\",\"string\":\""
                + Bech32.encode(ChainJson.hrpFor(BlockProcessor.params.type), version, hash) + "\"}";
    }

    private String headerFieldsJson(byte[] header, int height, boolean block) {
        int bits = HeaderUtil.bits(header);
        boolean genesis = height == 0;
        return "\"hash\":\"" + hex(HeaderUtil.hash(header)) + "\","
                + "\"confirmations\":" + getConfirmations(height) + ",";
    }

    private String headerTailJson(byte[] header, int height) {
        int bits = HeaderUtil.bits(header);
        String prev = height == 0 ? "null" : "\"" + hex(HeaderUtil.prevBlock(header)) + "\"";
        return "\"time\":" + HeaderUtil.time(header) + ","
                + "\"mediantime\":" + computeMedianTime(height) + ","
                + "\"nonce\":" + (HeaderUtil.nonce(header) & 0xFFFFFFFFL) + ","
                + "\"extranonce\":\"" + hex(HeaderUtil.extraNonce(header)) + "\","
                + "\"bits\":\"" + hex32(bits) + "\","
                + "\"difficulty\":" + number(toDifficulty(bits)) + ","
                + "\"chainwork\":\"" + chainwork64(db.getChainwork(height)) + "\"";
    }

    private String rootsJson(byte[] header) {
        return "\"version\":" + (HeaderUtil.version(header) & 0xFFFFFFFFL) + ","
                + "\"versionHex\":\"" + hex32(HeaderUtil.version(header)) + "\","
                + "\"merkleroot\":\"" + hex(HeaderUtil.merkleRoot(header)) + "\","
                + "\"witnessroot\":\"" + hex(HeaderUtil.witnessRoot(header)) + "\","
                + "\"treeroot\":\"" + hex(HeaderUtil.treeRoot(header)) + "\","
                + "\"reservedroot\":\"" + hex(HeaderUtil.reservedRoot(header)) + "\","
                + "\"mask\":\"" + hex(HeaderUtil.mask(header)) + "\",";
    }

    private String nextHashJson(int height) {
        return "\"nextblockhash\":" + getNextBlockHashOrNull(height);
    }

    /** hsd's headerToJSON. */
    private String headerToJson(byte[] header, int height) {
        if (header == null || header.length < 236) return "null";
        return "{" + headerFieldsJson(header, height, false)
                + "\"height\":" + height + ","
                + rootsJson(header)
                + headerTailJson(header, height) + ","
                + "\"previousblockhash\":" + (height == 0 ? "null" : "\"" + hex(HeaderUtil.prevBlock(header)) + "\"") + ","
                + nextHashJson(height) + "}";
    }

    /** hsd's blockToJSON; {@code details} puts full transaction objects in "tx" instead of ids. */
    private String blockToJson(byte[] rawBlock, int height, boolean details) {
        byte[] header = Arrays.copyOf(rawBlock, Math.min(236, rawBlock.length));
        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
        int count = txs.size();
        int strippedSize = 236 + (count < 0xFD ? 1 : count <= 0xFFFF ? 3 : 5);
        for (TxParser.ParsedTx tx : txs) strippedSize += tx.baseSize;
        long weight = (long) strippedSize * 3 + rawBlock.length;
        String bh = hex(HeaderUtil.hash(header));
        long btime = HeaderUtil.time(header);

        StringBuilder sb = new StringBuilder("{");
        sb.append(headerFieldsJson(header, height, true));
        sb.append("\"strippedsize\":").append(strippedSize).append(",");
        sb.append("\"size\":").append(rawBlock.length).append(",");
        sb.append("\"weight\":").append(weight).append(",");
        sb.append("\"height\":").append(height).append(",");
        sb.append(rootsJson(header));
        if (!details) {
            sb.append("\"coinbase\":[");
            if (!txs.isEmpty() && !txs.get(0).inputs.isEmpty()) {
                List<byte[]> witness = txs.get(0).inputs.get(0).witness;
                for (int i = 0; i < witness.size(); i++) {
                    if (i > 0) sb.append(",");
                    sb.append("\"").append(hex(witness.get(i))).append("\"");
                }
            }
            sb.append("],");
        }
        sb.append("\"tx\":[");
        for (int i = 0; i < count; i++) {
            if (i > 0) sb.append(",");
            if (details) sb.append(rpcTx(txs.get(i), bh, btime, height));
            else sb.append("\"").append(TxParser.computeTxid(txs.get(i).raw)).append("\"");
        }
        sb.append("],");
        sb.append(headerTailJson(header, height)).append(",");
        sb.append("\"nTx\":").append(count).append(",");
        sb.append("\"previousblockhash\":").append(height == 0 ? "null" : "\"" + hex(HeaderUtil.prevBlock(header)) + "\"").append(",");
        sb.append(nextHashJson(height)).append("}");
        return sb.toString();
    }

    /** hsd's txToJSON (rpc.js). {@code blockHash} null = not in a block. */
    private String rpcTx(TxParser.ParsedTx tx, String blockHash, long blockTime, int height) {
        boolean coinbase = !tx.inputs.isEmpty() && tx.inputs.get(0).isCoinbase();
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"txid\":\"").append(hex(ChainJson.txid(tx))).append("\",");
        sb.append("\"hash\":\"").append(hex(P2pMessages.wtxid(tx))).append("\",");
        sb.append("\"size\":").append(tx.totalSize).append(",");
        sb.append("\"vsize\":").append(Mempool.virtualSizeOf(tx)).append(",");
        sb.append("\"version\":").append(tx.version & 0xFFFFFFFFL).append(",");
        sb.append("\"locktime\":").append(tx.locktime & 0xFFFFFFFFL).append(",");
        sb.append("\"vin\":[");
        for (int i = 0; i < tx.inputs.size(); i++) {
            TxParser.Input in = tx.inputs.get(i);
            if (i > 0) sb.append(",");
            sb.append("{\"coinbase\":").append(coinbase)
                    .append(",\"txid\":\"").append(hex(in.prevHash)).append("\"")
                    .append(",\"vout\":").append(in.prevIndex & 0xFFFFFFFFL)
                    .append(",\"txinwitness\":[");
            for (int w = 0; w < in.witness.size(); w++) {
                if (w > 0) sb.append(",");
                sb.append("\"").append(hex(in.witness.get(w))).append("\"");
            }
            sb.append("],\"sequence\":").append(in.sequence & 0xFFFFFFFFL).append("}");
        }
        sb.append("],\"vout\":[");
        for (int i = 0; i < tx.outputs.size(); i++) {
            TxParser.Output o = tx.outputs.get(i);
            if (i > 0) sb.append(",");
            sb.append("{\"value\":").append(coinAmount(o.value)).append(",\"n\":").append(i)
                    .append(",\"address\":").append(addrJson(o.addrVersion, o.addrHash))
                    .append(",\"covenant\":").append(ChainJson.covenantJson(o.covenant)).append("}");
        }
        sb.append("],\"blockhash\":").append(blockHash == null ? "null" : "\"" + blockHash + "\"");
        sb.append(",\"confirmations\":").append(blockHash == null ? 0 : Math.max(0, db.getBlockTip() - height + 1));
        sb.append(",\"time\":").append(blockHash == null ? 0 : blockTime);
        sb.append(",\"blocktime\":").append(blockHash == null ? 0 : blockTime);
        return sb.append("}").toString();
    }

    /** hsd's gettxout result. */
    private String coinOutJson(long value, int addrVersion, byte[] addrHash, int version, boolean coinbase, int coinHeight) {
        int tip = db.getBlockTip();
        return "{\"bestblock\":\"" + hex(HeaderUtil.hash(db.getHeader(tip))) + "\","
                + "\"confirmations\":" + (coinHeight < 0 ? 0 : Math.max(0, tip - coinHeight + 1)) + ","
                + "\"value\":" + coinAmount(value) + ","
                + "\"address\":" + addrJson(addrVersion, addrHash) + ","
                + "\"version\":" + version + ","
                + "\"coinbase\":" + coinbase + "}";
    }

    private String nameEntryToJson(ChainDB.NameEntry e, String name) {
        return "{\"result\":{"
                + "\"start\":{\"reserved\":false,\"week\":0,\"start\":"
                + e.height + ",\"locked\":false},"
                + "\"info\":{"
                + "\"name\":\"" + e.name + "\","
                + "\"nameHash\":\"" + e.nameHash + "\","
                + "\"state\":\"" + e.state + "\","
                + "\"height\":" + e.height + ","
                + "\"renewal\":" + e.renewal + ","
                + "\"owner\":{\"hash\":\"" + e.ownerTxid
                + "\",\"index\":" + e.ownerIndex + "},"
                + "\"value\":" + e.value + ","
                + "\"highest\":" + e.highest + ","
                + "\"claimed\":" + e.claimed + ","
                + "\"renewals\":" + e.renewals + ","
                + "\"registered\":" + "CLOSED".equals(e.state) + ","
                + "\"expired\":false,"
                + "\"weak\":" + e.weak + ","
                + "\"transfer\":" + e.transfer + ","
                + "\"revoked\":" + e.revoked
                + "}}}";
    }

    // ── Auth ──────────────────────────────────────────────────────────────────


    // ── Step 3c: remaining hsd node RPCs ──────────────────────────────────────

    /** compacttree / reconstructtree / resetrootcache: this node keeps its tree consistent by itself. */
    private String noArgsNull(String params, String name) throws RpcException {
        if (!parseParamList(params).isEmpty()) throw new RpcException(-1, name);
        return "null";
    }

    /** hsd checks only its arguments here (level and numblocks must both be given) and returns null. */
    private String verifyChain(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.size() > 2) throw new RpcException(-1, "verifychain ( checklevel numblocks )");
        if (pl.size() < 2) throw new RpcException(-3, "Missing parameters.");
        try { Long.parseLong(pl.get(0).trim()); Long.parseLong(pl.get(1).trim()); }
        catch (NumberFormatException e) { throw new RpcException(-3, "Missing parameters."); }
        return "null";
    }

    /** No priority statistics are kept: hsd answers -1 while its estimator has too little data. */
    private String estimatePriority(String params, boolean smart) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.size() != 1) throw new RpcException(-1, smart ? "estimatesmartpriority nblocks" : "estimatepriority nblocks");
        int blocks = parseIntParamOrDefault(params, 0, 1);
        if (blocks <= 0) blocks = 1;
        return smart ? "{\"priority\":-1,\"blocks\":" + blocks + "}" : "-1";
    }

    private String invalidateBlock(String params, boolean invalidate) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.size() != 1) throw new RpcException(-1, invalidate ? "invalidateblock \"hash\"" : "reconsiderblock \"hash\"");
        String hs = parseStringParam(params, 0);
        byte[] hash;
        try {
            if (hs == null || hs.length() != 64) throw new IllegalArgumentException();
            hash = fromHex(hs);
        } catch (RuntimeException e) {
            throw new RpcException(-3, "Invalid block hash.");
        }
        if (chainSync == null) throw new RpcException(-1, "Node is not ready.");
        String err = invalidate ? chainSync.invalidateBlock(hash) : chainSync.reconsiderBlock(hash);
        if (err != null) throw new RpcException(-1, err);
        return "null";
    }

    /** POST /reset {height}: hsd's chain.reset. */
    private RestApi.Response restReset(String body) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"height\"\\s*:\\s*\"?(\\d+)\"?").matcher(body == null ? "" : body);
        if (!m.find()) return restError("Height is required.");
        long height = Long.parseLong(m.group(1));
        if (chainSync == null) return restError("Node is not ready.");
        if (height > db.getBlockTip()) return restError("Height cannot be greater than chain tip.");
        String err = chainSync.resetChain((int) height);
        return err == null ? new RestApi.Response(200, "{\"success\":true}") : restError(err);
    }

    private static RestApi.Response restError(String msg) {
        return new RestApi.Response(400, "{\"error\":{\"type\":\"Error\",\"message\":\"" + JsonUtil.escape(msg) + "\"}}");
    }

    private String decodeResource(String params) throws RpcException {
        if (parseParamList(params).size() != 1) throw new RpcException(-1, "decoderesource \"hex\"");
        String hx = parseStringParam(params, 0);
        byte[] data;
        try { data = fromHex(hx == null ? "" : hx); } catch (RuntimeException e) { throw new RpcException(-3, "Invalid hex."); }
        if (data.length == 0) throw new RpcException(-3, "Invalid hex.");
        return DnsResource.decodeToJson(data);
    }

    /** Parses {"records":[{"type":"NS",...},...]}, encodes it and returns the normalized JSON, as hsd does. */
    private String validateResource(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.isEmpty() || pl.size() > 2) throw new RpcException(-1, "validateresource '{\"records\": [{...}]}'");
        java.util.LinkedHashMap<String, String> top = parseObjectParam(params, 0);
        String recs = top.get("records");
        if (recs == null) throw new RpcException(-3, "Invalid resource object.");
        List<DnsResource.Record> out = new ArrayList<>();
        List<String> specs = parseStringArrayParam("[" + recs + "]", 0);
        try {
            if (specs != null) for (String spec : specs) {
                java.util.LinkedHashMap<String, String> f = parseObjectParam("[" + spec + "]", 0);
                String type = unquote(f.get("type"));
                if (type == null) throw new IllegalArgumentException("Unknown record type.");
                switch (type) {
                    case "NS" -> out.add(new DnsResource.NsRecord(req(f, "ns")));
                    case "GLUE4" -> out.add(new DnsResource.Glue4Record(req(f, "ns"), req(f, "address")));
                    case "GLUE6" -> out.add(new DnsResource.Glue6Record(req(f, "ns"), req(f, "address")));
                    case "SYNTH4" -> out.add(new DnsResource.Synth4Record(req(f, "address")));
                    case "SYNTH6" -> out.add(new DnsResource.Synth6Record(req(f, "address")));
                    case "TXT" -> {
                        List<String> items = new ArrayList<>();
                        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"")
                                .matcher(f.getOrDefault("txt", "[]"));
                        while (m.find()) items.add(m.group(1).replace("\\\"", "\"").replace("\\\\", "\\"));
                        out.add(new DnsResource.TxtRecord(items));
                    }
                    case "DS" -> out.add(new DnsResource.DsRecord(
                            Integer.parseInt(f.get("keyTag").trim()), Integer.parseInt(f.get("algorithm").trim()),
                            Integer.parseInt(f.get("digestType").trim()), fromHex(req(f, "digest"))));
                    default -> throw new IllegalArgumentException("Unknown record type: " + type);
                }
            }
            return DnsResource.decodeToJson(DnsResource.encode(out));
        } catch (RuntimeException e) {
            throw new RpcException(-32700, String.valueOf(e.getMessage()));
        }
    }

    private static String req(java.util.Map<String, String> f, String key) {
        String v = unquote(f.get(key));
        if (v == null) throw new IllegalArgumentException("Missing field: " + key);
        return v;
    }

    /** hsd's rules.grindName: a random a-z name that is not blacklisted, reserved or still waiting for its rollout week. */
    private String grindName(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.size() > 1) throw new RpcException(-1, "grindname size");
        int size = pl.isEmpty() ? 10 : parseIntParamOrDefault(params, 0, -1);
        if (size < 1 || size > 63) throw new RpcException(-3, "Invalid length.");
        int height = Math.max(db.getBlockTip() + 1, BlockProcessor.params.auctionStart);
        java.util.Random rnd = new java.security.SecureRandom();
        for (int i = 0; i < 500_000; i++) {
            char[] c = new char[size];
            for (int j = 0; j < size; j++) c[j] = (char) ('a' + rnd.nextInt(26));
            String name = new String(c);
            if (!HandshakeCovenantRules.verifyName(name.getBytes(StandardCharsets.US_ASCII))) continue; // blacklist
            byte[] hash = UrkelNameHash.hashName(name);
            if ("main".equals(BlockProcessor.params.type) && !HandshakeCovenantRules.hasRollout(hash, height)) continue; // the rollout schedule is mainnet's
            if (ReservedNames.get(hash) != null) continue;
            return "\"" + name + "\"";
        }
        throw new RpcException(-1, "Could not find available name.");
    }

    /** Node extension: stores the address that mining rewards (getwork / setgenerate) are paid to; "" clears it. */
    private String setMinerAddress(String params) throws RpcException {
        if (parseParamList(params).size() != 1) throw new RpcException(-1, "setmineraddress \"address\"");
        String addr = String.valueOf(parseStringParam(params, 0)).trim();
        if (!addr.isEmpty()) MiningService.decodeAddress(addr);      // throws -5 on a bad address
        config.setMinerAddress(addr);
        return "null";
    }

    private static String jsonString(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private String setLogLevel(String params) throws RpcException {
        if (parseParamList(params).size() != 1) throw new RpcException(-1, "setloglevel \"level\"");
        String level = String.valueOf(parseStringParam(params, 0)).toLowerCase();
        if (!List.of("none", "error", "warning", "info", "debug", "spam").contains(level))
            throw new RpcException(-8, "Invalid log level.");
        config.set("log.level", level);
        return "null";
    }

    /**
     * hsd's signrawtransaction for standard pay-to-pubkey-hash inputs: signs every input it holds a key for.
     * Coins come from the optional previous-outputs list ({txid, vout, address, amount}) or, failing that,
     * from the mempool / chain. Returns {hex, complete}.
     */
    private String signRawTransaction(String params) throws RpcException {
        List<String> pl = parseParamList(params);
        if (pl.isEmpty() || pl.size() > 4)
            throw new RpcException(-1, "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"address\":\"bech32\",\"amount\":n}] [\"privatekey1\",...] sighashtype )");
        byte[] raw;
        try { raw = fromHex(String.valueOf(parseStringParam(params, 0))); } catch (RuntimeException e) { throw new RpcException(-3, "Invalid hex string."); }
        TxParser.ParsedTx tx = TxParser.parse(raw);
        if (tx == null) throw new RpcException(-22, "TX decode failed");

        // keys, by the hash of their public key
        java.util.Map<String, byte[]> keys = new java.util.HashMap<>();
        if (pl.size() > 2) {
            List<String> secrets = parseStringArrayParam(params, 2);
            if (secrets != null) for (String sec : secrets) {
                String w = unquote(sec);
                if (w == null || w.isEmpty()) continue;
                try {
                    byte[] payload = Base58.decodeCheck(w);
                    if (payload.length < 33) throw new IllegalArgumentException();
                    byte[] priv = Arrays.copyOfRange(payload, 1, 33);
                    keys.put(hex(Blake2b.hash(Secp256k1.compressedPublicKey(priv), 20)), priv);
                } catch (Exception e) {
                    throw new RpcException(-5, "Invalid private key.");
                }
            }
        }

        int type = TxVerify.SIGHASH_ALL;
        if (pl.size() > 3) {
            String sh = unquote(pl.get(3));
            if (sh != null && !sh.isEmpty() && !sh.equals("null")) {
                String[] parts = sh.split("\\|");
                type = switch (parts[0]) {
                    case "ALL" -> TxVerify.SIGHASH_ALL;
                    case "NONE" -> TxVerify.SIGHASH_NONE;
                    case "SINGLE" -> TxVerify.SIGHASH_SINGLE;
                    case "SINGLEREVERSE" -> TxVerify.SIGHASH_SINGLEREVERSE;
                    default -> throw new RpcException(-8, "Invalid sighash type.");
                };
                if (parts.length == 2) {
                    if (parts[1].equals("NOINPUT")) type |= TxVerify.SIGHASH_NOINPUT;
                    else if (parts[1].equals("ANYONECANPAY")) type |= TxVerify.SIGHASH_ANYONECANPAY;
                    else throw new RpcException(-8, "Invalid sighash type.");
                } else if (parts.length > 2) throw new RpcException(-8, "Invalid sighash type.");
            }
        }

        // coins named by the caller
        java.util.Map<String, long[]> given = new java.util.HashMap<>();      // outpoint -> {value}
        java.util.Map<String, byte[]> givenHash = new java.util.HashMap<>();
        if (pl.size() > 1) {
            List<String> specs = parseStringArrayParam(params, 1);
            if (specs != null) for (String spec : specs) {
                java.util.LinkedHashMap<String, String> f = parseObjectParam("[" + spec + "]", 0);
                try {
                    String id = req(f, "txid");
                    int vout = Integer.parseInt(f.get("vout").trim());
                    Object[] a = Bech32.decode(req(f, "address"));
                    long value = Math.round(Double.parseDouble(f.get("amount").trim()) * 1_000_000.0);
                    if ((int) a[1] == 0) {
                        given.put(id + ":" + vout, new long[]{value});
                        givenHash.put(id + ":" + vout, (byte[]) a[2]);
                    }
                } catch (RuntimeException e) {
                    throw new RpcException(-8, "Invalid UTXO.");
                }
            }
        }

        ChainJson cj = new ChainJson(db, mempool);
        int n = tx.inputs.size();
        List<List<byte[]>> wit = new ArrayList<>();
        boolean complete = true;
        for (int i = 0; i < n; i++) {
            TxParser.Input in = tx.inputs.get(i);
            List<byte[]> stack = new ArrayList<>(in.witness);
            wit.add(stack);
            if (in.isCoinbase()) continue;
            String op = hex(in.prevHash) + ":" + in.prevIndex;
            byte[] ah; long value;
            if (given.containsKey(op)) { ah = givenHash.get(op); value = given.get(op)[0]; }
            else {
                ChainJson.Coin c = cj.resolve(in.prevHash, in.prevIndex);
                if (c == null || c.out().addrVersion != 0) { complete = false; continue; }
                ah = c.out().addrHash; value = c.out().value;
            }
            byte[] priv = ah.length == 20 ? keys.get(hex(ah)) : null;
            if (priv != null) {
                byte[] sig = TxVerify.signInput(tx, i, ah, value, priv, type);
                stack.clear();
                stack.add(sig);
                stack.add(Secp256k1.compressedPublicKey(priv));
            }
            // judged on what is now in the witness, not on whether we signed
            TxParser.ParsedTx probe = withWitness(tx, wit, i);
            if (probe == null || !TxVerify.verifyInput(probe, i, ah, value)) complete = false;
        }
        TxParser.ParsedTx signed = withWitness(tx, wit, n);
        if (signed == null) throw new RpcException(-22, "TX encode failed");
        return "{\"hex\":\"" + hex(signed.raw) + "\",\"complete\":" + complete + "}";
    }

    /** The transaction with the given per-input witness stacks (inputs at or after {@code upTo} keep theirs). */
    private static TxParser.ParsedTx withWitness(TxParser.ParsedTx tx, List<List<byte[]>> wit, int upTo) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(tx.raw, 0, tx.baseSize);
        for (int i = 0; i < tx.inputs.size(); i++) {
            List<byte[]> st = i < wit.size() ? wit.get(i) : tx.inputs.get(i).witness;
            BlockTemplates.writeVarint(o, st.size());
            for (byte[] item : st) { BlockTemplates.writeVarint(o, item.length); o.write(item, 0, item.length); }
        }
        return TxParser.parse(o.toByteArray());
    }

    private boolean checkAuth(HttpExchange ex) {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        if (auth == null || !auth.startsWith("Basic ")) return false;
        try {
            String decoded = new String(
                    Base64.getDecoder().decode(auth.substring(6)),
                    StandardCharsets.UTF_8);
            // Format: "x:apikey"
            String expectedKey = config.getApiKey();
            return decoded.equals("x:" + expectedKey);
        } catch (Exception e) {
            return false;
        }
    }

    // ── Response helpers ──────────────────────────────────────────────────────

    private void respond(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.getResponseBody().flush();
    }

    private static String success(String id, String result) {
        return "{\"result\":" + result + ",\"error\":null,\"id\":" + id + "}";
    }

    private static String error(String id, int code, String message) {
        return "{\"result\":null,\"error\":{\"code\":" + code
                + ",\"message\":\"" + escape(message) + "\"},\"id\":" + id + "}";
    }

    // ── JSON parsing helpers ──────────────────────────────────────────────────

    private static String extractString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        idx = json.indexOf(":", idx + search.length());
        if (idx < 0) return null;
        idx++;
        while (idx < json.length() && Character.isWhitespace(json.charAt(idx))) idx++;
        if (idx >= json.length()) return null;
        if (json.charAt(idx) == '"') {
            int end = json.indexOf('"', idx + 1);
            return end < 0 ? null : json.substring(idx + 1, end);
        }
        int end = idx;
        while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') end++;
        return json.substring(idx, end).trim();
    }

    private static String extractId(String json) {
        String id = extractString(json, "id");
        if (id == null) return "null";
        // Check if numeric
        try { Long.parseLong(id); return id; } catch (NumberFormatException e) {}
        return "\"" + id + "\"";
    }

    private static String extractParams(String json) {
        int idx = json.indexOf("\"params\"");
        if (idx < 0) return "[]";
        idx = json.indexOf("[", idx);
        if (idx < 0) return "[]";
        int depth = 0, end = idx;
        while (end < json.length()) {
            char c = json.charAt(end);
            if (c == '[') depth++;
            else if (c == ']') { if (--depth == 0) { end++; break; } }
            end++;
        }
        return json.substring(idx, end);
    }

    private static String parseStringParam(String params, int index) {
        List<String> list = parseParamList(params);
        if (index >= list.size()) return null;
        String v = list.get(index).trim();
        if (v.startsWith("\"") && v.endsWith("\""))
            return v.substring(1, v.length() - 1);
        return v;
    }

    private static int parseIntParam(String params, int index) throws RpcException {
        String v = parseStringParam(params, index);
        if (v == null) throw new RpcException(-8, "Missing parameter " + index);
        try { return Integer.parseInt(v.trim()); }
        catch (NumberFormatException e) {
            throw new RpcException(-8, "Invalid integer: " + v);
        }
    }

    private static boolean parseBoolParam(String params, int index, boolean def) {
        String v = parseStringParam(params, index);
        if (v == null) return def;
        return "true".equalsIgnoreCase(v) || "1".equals(v);
    }

    /** Parses a JSON array parameter (e.g. a list of txids) at the given
     *  top-level index, reusing parseParamList's depth-aware splitting
     *  recursively on the sub-array's own contents. */
    private static List<String> parseStringArrayParam(String params, int index) {
        List<String> list = parseParamList(params);
        if (index >= list.size()) return null;
        String raw = list.get(index).trim();
        if (!raw.startsWith("[") || !raw.endsWith("]")) return null;
        List<String> items = parseParamList(raw);
        List<String> result = new ArrayList<>();
        for (String item : items) {
            String s = item.trim();
            if (s.startsWith("\"") && s.endsWith("\"")) s = s.substring(1, s.length() - 1);
            result.add(s);
        }
        return result;
    }

    /** Parses a flat JSON object param (e.g. {"address":amount,...}) into
     *  an ordered key->raw-value map. Values are returned as their raw
     *  JSON text (quotes still attached for strings) since callers need
     *  to know whether a value was a string or a number, not just its
     *  content. Reuses parseParamList's depth-aware splitting, which
     *  already treats { and [ identically for nesting purposes -- it
     *  just needs the outer braces stripped first instead of brackets. */
    private static java.util.LinkedHashMap<String, String> parseObjectParam(String params, int index) {
        List<String> list = parseParamList(params);
        java.util.LinkedHashMap<String, String> result = new java.util.LinkedHashMap<>();
        if (index >= list.size()) return result;
        String raw = list.get(index).trim();
        if (!raw.startsWith("{") || !raw.endsWith("}")) return result;
        String inner = raw.substring(1, raw.length() - 1);
        List<String> fields = parseParamList("[" + inner + "]"); // reuse the same splitter
        for (String field : fields) {
            int colonPos = findTopLevelColon(field);
            if (colonPos < 0) continue;
            String key = field.substring(0, colonPos).trim();
            if (key.startsWith("\"") && key.endsWith("\"")) key = key.substring(1, key.length() - 1);
            String value = field.substring(colonPos + 1).trim();
            result.put(key, value);
        }
        return result;
    }

    private static int findTopLevelColon(String s) {
        boolean inString = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') inString = !inString;
            else if (c == ':' && !inString) return i;
        }
        return -1;
    }

    private static List<String> parseParamList(String params) {
        List<String> list = new ArrayList<>();
        if (params == null || params.equals("[]")) return list;
        String inner = params.trim();
        if (inner.startsWith("[")) inner = inner.substring(1);
        if (inner.endsWith("]")) inner = inner.substring(0, inner.length() - 1);
        // Simple split — handles strings and numbers but not nested objects
        int depth = 0; int start = 0;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            else if (c == ',' && depth == 0) {
                list.add(inner.substring(start, i).trim());
                start = i + 1;
            }
        }
        String last = inner.substring(start).trim();
        if (!last.isEmpty()) list.add(last);
        return list;
    }

    // ── Block/hash resolution ─────────────────────────────────────────────────

    private byte[] resolveHeader(String hashOrHeight) {
        try {
            return db.getHeader(Integer.parseInt(hashOrHeight));
        } catch (NumberFormatException e) {
            String hash = hashOrHeight.replace("\"", "");
            if (hash.length() != 64) return null;
            try {
                int h = db.getHeightByHash(hash);
                return h < 0 ? null : db.getHeader(h);
            } catch (RuntimeException bad) { return null; }
        }
    }

    private int resolveHeight(String hashOrHeight) throws RpcException {
        hashOrHeight = hashOrHeight.replace("\"", "");
        try {
            return Integer.parseInt(hashOrHeight);
        } catch (NumberFormatException e) {
            int h = -1;
            try { if (hashOrHeight.length() == 64) h = db.getHeightByHash(hashOrHeight); } catch (RuntimeException ignored) { }
            if (h < 0) throw new RpcException(-5, "Block not found: " + hashOrHeight);
            return h;
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    // FIX: a dead, zero-call-site readLE32(byte[], int) used to live here --
    // confirmed via grep across the whole file before removal. Deleted as
    // part of the project's dead-code cleanup pass.

    private static String hex(byte[] b) {
        if (b == null) return "";
        return HexUtil.encode(b);
    }

    private static String jsonEscape(String s) {
        return JsonUtil.escape(s);
    }

    private static byte[] fromHex(String s) {
        s = s.replace("\"", "");
        return HexUtil.decode(s);
    }

    static String escape(String s) {
        // FIX: used to escape only '\\' and '"', leaving '\n'/'\r'
        // unescaped in RPC error messages -- the same latent bug
        // WebAdminServer's own jsonEscape() had, just rarely exercised
        // here since error messages rarely contain raw newlines. Now
        // delegates to the single shared, complete implementation.
        return JsonUtil.escape(s);
    }

    // ── RPC exception ─────────────────────────────────────────────────────────

    public static class RpcException extends Exception {
        public final int code;
        public RpcException(int code, String message) {
            super(message);
            this.code = code;
        }
    }
}