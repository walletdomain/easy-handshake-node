package handshake.node.server;

import handshake.node.chain.BlockProcessor;
import handshake.node.chain.ConsensusRules;
import handshake.node.chain.HeaderUtil;
import handshake.node.chain.Mempool;
import handshake.node.chain.P2pMessages;
import handshake.node.chain.TxParser;
import handshake.node.crypto.Bech32;
import handshake.node.crypto.Blake2b;
import handshake.node.storage.ChainDB;
import handshake.node.storage.IndexStore;
import handshake.node.util.HexUtil;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON for the REST API, field-for-field what hsd's getJSON() methods emit (key order and omissions included),
 * so a client written for hsd (Bob wallet, bcurl, hs-client) reads our answers unchanged.
 *
 * One instance per request: it carries a small block cache (bounded to {@link #CACHE_BLOCKS} parsed blocks) so
 * resolving the inputs of many transactions of the same block does not re-read and re-parse that block each time.
 */
final class ChainJson {
    static final int CACHE_BLOCKS = 16;

    private final ChainDB db;
    private final Mempool mempool;
    private final String hrp;

    private final LinkedHashMap<Integer, List<TxParser.ParsedTx>> cache = new LinkedHashMap<>(32, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<Integer, List<TxParser.ParsedTx>> e) {
            return size() > CACHE_BLOCKS;
        }
    };

    ChainJson(ChainDB db, Mempool mempool) {
        this.db = db;
        this.mempool = mempool;
        this.hrp = hrpFor(BlockProcessor.params.type);
    }

    static String hrpFor(String networkType) {
        return switch (networkType) {
            case "main" -> "hs";
            case "testnet" -> "ts";
            case "regtest" -> "rs";
            case "simnet" -> "ss";
            default -> "hs";
        };
    }

    String hrp() { return hrp; }

    // ── small helpers ────────────────────────────────────────────────────────

    static String hex(byte[] b) { return HexUtil.encode(b); }

    static byte[] txid(TxParser.ParsedTx t) { return Blake2b.hash256(Arrays.copyOf(t.raw, t.baseSize)); }

    String address(int version, byte[] hash) { return Bech32.encode(hrp, version, hash); }

    /** A parsed output paired with where it lives. height -1 = in the mempool. */
    record Coin(TxParser.Output out, int height, boolean coinbase, int version) {}

    static String covenantJson(TxParser.Covenant c) {
        StringBuilder sb = new StringBuilder("{\"type\":").append(c.type)
                .append(",\"action\":\"").append(actionName(c.type)).append("\",\"items\":[");
        for (int i = 0; i < c.items.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(hex(c.items.get(i).data == null ? new byte[0] : c.items.get(i).data)).append('"');
        }
        return sb.append("]}").toString();
    }

    static String actionName(int type) {
        return switch (type) {
            case TxParser.COV_NONE -> "NONE";
            case TxParser.COV_CLAIM -> "CLAIM";
            case TxParser.COV_OPEN -> "OPEN";
            case TxParser.COV_BID -> "BID";
            case TxParser.COV_REVEAL -> "REVEAL";
            case TxParser.COV_REDEEM -> "REDEEM";
            case TxParser.COV_REGISTER -> "REGISTER";
            case TxParser.COV_UPDATE -> "UPDATE";
            case TxParser.COV_RENEW -> "RENEW";
            case TxParser.COV_TRANSFER -> "TRANSFER";
            case TxParser.COV_FINALIZE -> "FINALIZE";
            case TxParser.COV_REVOKE -> "REVOKE";
            default -> "NONE";
        };
    }

    // ── block / transaction access ───────────────────────────────────────────

    List<TxParser.ParsedTx> blockTxs(int height) {
        List<TxParser.ParsedTx> l = cache.get(height);
        if (l != null) return l;
        byte[] raw = db.getBlock(height);
        if (raw == null) return null;
        l = BlockProcessor.parseBlockTxs(raw);
        cache.put(height, l);
        return l;
    }

    /** Location of a confirmed transaction, or null (also when the tx index is off). */
    IndexStore.TxLoc locate(byte[] txid) {
        IndexStore idx = db.index();
        return idx == null ? null : idx.txLocation(txid);
    }

    /** The confirmed transaction at a location, verified against the id it was looked up by. */
    TxParser.ParsedTx txAt(IndexStore.TxLoc loc, byte[] txid) {
        List<TxParser.ParsedTx> txs = blockTxs(loc.height());
        if (txs == null || loc.pos() >= txs.size()) return null;
        TxParser.ParsedTx t = txs.get(loc.pos());
        return txid == null || Arrays.equals(txid(t), txid) ? t : null;
    }

    /** Output {@code index} of transaction {@code prev}, from the mempool first, then the chain. */
    Coin resolve(byte[] prev, int index) {
        if (mempool != null) {
            byte[] raw = mempool.getRaw(hex(prev));
            if (raw != null) {
                TxParser.ParsedTx t = TxParser.parse(raw);
                if (t != null && index >= 0 && index < t.outputs.size())
                    return new Coin(t.outputs.get(index), -1, false, t.version);
            }
        }
        IndexStore.TxLoc loc = locate(prev);
        if (loc == null) return null;
        TxParser.ParsedTx t = txAt(loc, prev);
        if (t == null || index < 0 || index >= t.outputs.size()) return null;
        return new Coin(t.outputs.get(index), loc.height(), loc.pos() == 0, t.version);
    }

    // ── transactions ─────────────────────────────────────────────────────────

    /** Where a transaction is, for the TXMeta wrapper; height -1 for the mempool. */
    record Meta(int height, byte[] blockHash, long time, int index, long mtime) {
        static Meta mempool(long mtime) { return new Meta(-1, null, 0, -1, mtime); }
    }

    /**
     * @param meta  null for a transaction inside a /block response (no height/block/time fields)
     * @param tipHeight used for "confirmations"; ignored when meta is null
     */
    String tx(TxParser.ParsedTx t, Meta meta, int blockIndex, long mtime, int tipHeight) {
        byte[] id = txid(t);
        boolean coinbase = !t.inputs.isEmpty() && t.inputs.get(0).isCoinbase();

        StringBuilder ins = new StringBuilder("[");
        long inValue = 0;
        boolean allCoins = !coinbase;
        for (int i = 0; i < t.inputs.size(); i++) {
            TxParser.Input in = t.inputs.get(i);
            if (i > 0) ins.append(',');
            Coin c = in.isCoinbase() ? null : resolve(in.prevHash, in.prevIndex);
            if (c == null) allCoins = false; else inValue += c.out().value;
            ins.append("{\"prevout\":{\"hash\":\"").append(hex(in.prevHash)).append("\",\"index\":")
                    .append(in.prevIndex & 0xFFFFFFFFL).append("},\"witness\":[");
            for (int w = 0; w < in.witness.size(); w++) {
                if (w > 0) ins.append(',');
                ins.append('"').append(hex(in.witness.get(w))).append('"');
            }
            ins.append("],\"sequence\":").append(in.sequence & 0xFFFFFFFFL);
            if (c != null) ins.append(",\"coin\":").append(coinBody(c));
            else ins.append(",\"address\":null");
            ins.append('}');
        }
        ins.append(']');

        long outValue = 0;
        StringBuilder outs = new StringBuilder("[");
        for (int i = 0; i < t.outputs.size(); i++) {
            TxParser.Output o = t.outputs.get(i);
            outValue += o.value;
            if (i > 0) outs.append(',');
            outs.append("{\"value\":").append(o.value).append(",\"address\":\"")
                    .append(address(o.addrVersion, o.addrHash)).append("\",\"covenant\":")
                    .append(covenantJson(o.covenant)).append('}');
        }
        outs.append(']');

        long fee = allCoins ? Math.max(0, inValue - outValue) : 0;
        long weight = (long) t.baseSize * 3 + t.totalSize;
        long vsize = (weight + 3) / 4;
        long rate = vsize == 0 ? 0 : fee * 1000 / vsize;

        StringBuilder sb = new StringBuilder("{\"hash\":\"").append(hex(id))
                .append("\",\"witnessHash\":\"").append(hex(P2pMessages.wtxid(t)))
                .append("\",\"fee\":").append(fee).append(",\"rate\":").append(rate)
                .append(",\"mtime\":").append(mtime);
        if (meta != null) {
            sb.append(",\"height\":").append(meta.height());
            sb.append(",\"block\":").append(meta.blockHash() == null ? "null" : "\"" + hex(meta.blockHash()) + "\"");
            sb.append(",\"time\":").append(meta.time());
            sb.append(",\"index\":").append(meta.index());
        } else {
            sb.append(",\"index\":").append(blockIndex);
        }
        sb.append(",\"version\":").append(t.version & 0xFFFFFFFFL)
                .append(",\"inputs\":").append(ins)
                .append(",\"outputs\":").append(outs)
                .append(",\"locktime\":").append(t.locktime & 0xFFFFFFFFL)
                .append(",\"hex\":\"").append(hex(t.raw)).append('"');
        if (meta != null) {
            int conf = meta.height() < 0 ? 0 : Math.max(0, tipHeight - meta.height() + 1);
            sb.append(",\"confirmations\":").append(conf);
        }
        return sb.append('}').toString();
    }

    private String coinBody(Coin c) {
        TxParser.Output o = c.out();
        return "{\"version\":" + c.version() + ",\"height\":" + c.height() + ",\"value\":" + o.value
                + ",\"address\":\"" + address(o.addrVersion, o.addrHash) + "\",\"covenant\":"
                + covenantJson(o.covenant) + ",\"coinbase\":" + c.coinbase() + "}";
    }

    /** A confirmed transaction's TXMeta JSON by location. */
    String confirmedTx(TxParser.ParsedTx t, int height, int pos, int tipHeight) {
        byte[] h = db.getHeader(height);
        byte[] bh = h == null ? null : HeaderUtil.hash(h);
        long time = h == null ? 0 : HeaderUtil.time(h);
        return tx(t, new Meta(height, bh, time, pos, time), pos, time, tipHeight);
    }

    // ── coins ────────────────────────────────────────────────────────────────

    String utxoCoin(byte[] txid, int index, ChainDB.UtxoEntry e) {
        TxParser.Covenant cov = ConsensusRules.decodeCovenant(e.covenantType(), e.covenantData());
        return "{\"version\":0,\"height\":" + e.height() + ",\"value\":" + e.value()
                + ",\"address\":\"" + address(e.addrVersion(), e.addrHash()) + "\",\"covenant\":"
                + covenantJson(cov) + ",\"coinbase\":" + e.coinbase()
                + ",\"hash\":\"" + hex(txid) + "\",\"index\":" + index + "}";
    }

    String mempoolCoin(TxParser.ParsedTx t, int index) {
        TxParser.Output o = t.outputs.get(index);
        return "{\"version\":" + (t.version & 0xFFFFFFFFL) + ",\"height\":-1,\"value\":" + o.value
                + ",\"address\":\"" + address(o.addrVersion, o.addrHash) + "\",\"covenant\":"
                + covenantJson(o.covenant) + ",\"coinbase\":false,\"hash\":\"" + hex(txid(t))
                + "\",\"index\":" + index + "}";
    }

    // ── headers / blocks ─────────────────────────────────────────────────────

    private static String headerFields(byte[] h, int height) {
        return "{\"hash\":\"" + hex(HeaderUtil.hash(h)) + "\",\"height\":" + height;
    }

    private static String headerTail(byte[] h) {
        return ",\"version\":" + (HeaderUtil.version(h) & 0xFFFFFFFFL)
                + ",\"prevBlock\":\"" + hex(HeaderUtil.prevBlock(h))
                + "\",\"merkleRoot\":\"" + hex(HeaderUtil.merkleRoot(h))
                + "\",\"witnessRoot\":\"" + hex(HeaderUtil.witnessRoot(h))
                + "\",\"treeRoot\":\"" + hex(HeaderUtil.treeRoot(h))
                + "\",\"reservedRoot\":\"" + hex(HeaderUtil.reservedRoot(h))
                + "\",\"time\":" + HeaderUtil.time(h)
                + ",\"bits\":" + (HeaderUtil.bits(h) & 0xFFFFFFFFL)
                + ",\"nonce\":" + (HeaderUtil.nonce(h) & 0xFFFFFFFFL)
                + ",\"extraNonce\":\"" + hex(HeaderUtil.extraNonce(h))
                + "\",\"mask\":\"" + hex(HeaderUtil.mask(h)) + "\"";
    }

    String header(byte[] h, int height) {
        BigInteger work = db.getChainwork(height);
        String cw = work == null ? "0" : work.toString(16);
        cw = "0".repeat(Math.max(0, 64 - cw.length())) + cw;
        return headerFields(h, height) + headerTail(h) + ",\"chainwork\":\"" + cw + "\"}";
    }

    String block(byte[] h, int height, int tipHeight, byte[] rawBlock) {
        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
        cache.put(height, txs);
        long btime = HeaderUtil.time(h);
        StringBuilder sb = new StringBuilder(headerFields(h, height));
        sb.append(",\"depth\":").append(tipHeight - height + 1).append(headerTail(h)).append(",\"txs\":[");
        for (int i = 0; i < txs.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(tx(txs.get(i), null, i, btime, tipHeight));
        }
        return sb.append("]}").toString();
    }
}