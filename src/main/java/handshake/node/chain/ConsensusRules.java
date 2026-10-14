package handshake.node.chain;

import handshake.node.crypto.Blake2b;
import handshake.node.storage.ChainDB;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Stateless transaction/covenant consensus rules, ported from hsd
 * (lib/primitives/tx.js checkSanity/isFinal/checkInputs and
 * lib/covenants/rules.js hasSaneCovenants/verifyCovenants/countX/hasNames).
 * Name-STATE dependent rules (chain.verifyCovenants) live in {@link NameRules}.
 */
public final class ConsensusRules {
    private ConsensusRules() {}

    public static final int NONE = 0, CLAIM = 1, OPEN = 2, BID = 3, REVEAL = 4, REDEEM = 5,
            REGISTER = 6, UPDATE = 7, RENEW = 8, TRANSFER = 9, FINALIZE = 10, REVOKE = 11;

    /** A consensus failure: hsd reject reason + DoS score. */
    public record Fail(String reason, int score) {}

    public static boolean isName(int type) { return type >= CLAIM && type <= REVOKE; }

    // ── Covenant item accessors (primitives/covenant.js) ─────────────────────

    public static byte[] item(TxParser.Covenant c, int i) {
        return c.items.get(i).data == null ? new byte[0] : c.items.get(i).data;
    }
    public static byte[] getHash(TxParser.Covenant c, int i) { return item(c, i); }
    public static long getU32(TxParser.Covenant c, int i) { return u32(item(c, i)); }
    public static int getU8(TxParser.Covenant c, int i) { return item(c, i)[0] & 0xff; }

    public static long u32(byte[] b) {
        return (b[0] & 0xffL) | ((b[1] & 0xffL) << 8) | ((b[2] & 0xffL) << 16) | ((b[3] & 0xffL) << 24);
    }

    // ── UTXO covenant codec ──────────────────────────────────────────────────
    // ChainDB.UtxoEntry.covenantData() holds the covenant ITEMS. The original
    // node format used a single length byte per item (corrupting items of
    // 256+ bytes); the current format is marked with a leading 0xFF:
    //   0xFF | varint(count) | { varint(len) | bytes }*
    // Legacy values (no marker) are decoded best-effort with 1-byte lengths.

    public static byte[] encodeCovenantItems(TxParser.Covenant cov) {
        if (cov == null || cov.items.isEmpty()) return new byte[0];
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(0xFF);
        BlockTemplates.writeVarint(o, cov.items.size());
        for (TxParser.CovenantItem it : cov.items) {
            byte[] d = it.data == null ? new byte[0] : it.data;
            BlockTemplates.writeVarint(o, d.length);
            o.write(d, 0, d.length);
        }
        return o.toByteArray();
    }

    public static TxParser.Covenant decodeCovenant(int type, byte[] data) {
        TxParser.Covenant c = new TxParser.Covenant();
        c.type = type;
        if (data == null || data.length == 0) return c;
        int p = 0;
        try {
            if ((data[0] & 0xff) == 0xFF) {
                p = 1;
                long[] r = readVarint(data, p); int count = (int) r[0]; p = (int) r[1];
                for (int i = 0; i < count; i++) {
                    r = readVarint(data, p); int len = (int) r[0]; p = (int) r[1];
                    TxParser.CovenantItem it = new TxParser.CovenantItem();
                    it.data = Arrays.copyOfRange(data, p, p + len);
                    p += len;
                    c.items.add(it);
                }
            } else {
                while (p < data.length) {
                    int len = data[p++] & 0xff;
                    TxParser.CovenantItem it = new TxParser.CovenantItem();
                    it.data = Arrays.copyOfRange(data, p, Math.min(data.length, p + len));
                    p += len;
                    c.items.add(it);
                }
            }
        } catch (RuntimeException e) {
            // damaged record: return what we have
        }
        return c;
    }

    private static long[] readVarint(byte[] b, int p) {
        int f = b[p] & 0xff;
        if (f < 0xfd) return new long[] { f, p + 1 };
        if (f == 0xfd) return new long[] { (b[p + 1] & 0xff) | ((b[p + 2] & 0xff) << 8), p + 3 };
        return new long[] { u32(Arrays.copyOfRange(b, p + 1, p + 5)), p + 5 };
    }

    // ── Name helpers ─────────────────────────────────────────────────────────

    public static byte[] hashName(byte[] name) { return HeaderUtil.sha3_256(name); }

    /** rules.blind(value, nonce) = blake2b-256(u64le(value) || nonce) */
    public static byte[] blind(long value, byte[] nonce) {
        byte[] b = new byte[40];
        for (int i = 0; i < 8; i++) b[i] = (byte) (value >>> (8 * i));
        System.arraycopy(nonce, 0, b, 8, 32);
        return Blake2b.hash256(b);
    }

    // ── Counting / uniqueness (rules.js) ─────────────────────────────────────

    public static int countOpens(TxParser.ParsedTx tx) {
        int n = 0;
        for (TxParser.Output o : tx.outputs) if (o.covenant.type == OPEN) n++;
        return n;
    }

    public static int countUpdates(TxParser.ParsedTx tx) {
        int n = 0;
        for (TxParser.Output o : tx.outputs) {
            switch (o.covenant.type) {
                case CLAIM: case OPEN: case UPDATE: case TRANSFER: case REVOKE: n++; break;
                default: break;
            }
        }
        return n;
    }

    public static int countRenewals(TxParser.ParsedTx tx) {
        int n = 0;
        for (TxParser.Output o : tx.outputs) {
            switch (o.covenant.type) {
                case REGISTER: case RENEW: case FINALIZE: n++; break;
                default: break;
            }
        }
        return n;
    }

    private static boolean uniqueType(int t) {
        switch (t) {
            case CLAIM: case OPEN: case REGISTER: case UPDATE: case RENEW: case TRANSFER: case FINALIZE: case REVOKE:
                return true;
            default:
                return false;
        }
    }

    /** rules.hasNames(tx, set): true when a unique-per-block covenant repeats a name already in {@code set}. */
    public static boolean hasNames(TxParser.ParsedTx tx, Set<String> set) {
        for (TxParser.Output o : tx.outputs) {
            if (!isName(o.covenant.type) || !uniqueType(o.covenant.type)) continue;
            if (set.contains(hex(getHash(o.covenant, 0)))) return true;
        }
        return false;
    }

    public static void addNames(TxParser.ParsedTx tx, Set<String> set) {
        for (TxParser.Output o : tx.outputs) {
            if (!isName(o.covenant.type) || !uniqueType(o.covenant.type)) continue;
            set.add(hex(getHash(o.covenant, 0)));
        }
    }

    // ── Transaction sanity (tx.checkSanity) ──────────────────────────────────

    public static boolean isCoinbase(TxParser.ParsedTx tx) {
        return !tx.inputs.isEmpty() && isNullPrevout(tx.inputs.get(0));
    }

    static boolean isNullPrevout(TxParser.Input in) {
        if (in.prevIndex != 0xFFFFFFFF) return false;
        for (byte b : in.prevHash) if (b != 0) return false;
        return true;
    }

    static int witnessSize(List<byte[]> w) {
        int s = BlockTemplates.varintSize(w.size());
        for (byte[] i : w) s += BlockTemplates.varintSize(i.length) + i.length;
        return s;
    }

    static boolean addressValid(int version, byte[] hash) {
        return version <= 31 && hash.length >= 2 && hash.length <= 40;
    }

    public static long weight(TxParser.ParsedTx tx) { return (long) tx.baseSize * 3 + tx.totalSize; }

    /** Returns null when valid. */
    public static Fail checkSanity(TxParser.ParsedTx tx) {
        if (tx.inputs.isEmpty()) return new Fail("bad-txns-vin-empty", 100);
        if (tx.outputs.isEmpty()) return new Fail("bad-txns-vout-empty", 100);
        if (tx.baseSize > ConsensusParams.MAX_TX_SIZE) return new Fail("bad-txns-oversize", 100);
        if (weight(tx) > ConsensusParams.MAX_TX_WEIGHT) return new Fail("bad-txns-overweight", 100);
        if (countOpens(tx) > ConsensusParams.MAX_BLOCK_OPENS) return new Fail("bad-txns-opens", 100);
        if (countUpdates(tx) > ConsensusParams.MAX_BLOCK_UPDATES) return new Fail("bad-txns-updates", 100);
        if (countRenewals(tx) > ConsensusParams.MAX_BLOCK_RENEWALS) return new Fail("bad-txns-renewals", 100);

        long total = 0;
        for (TxParser.Output o : tx.outputs) {
            if (o.value < 0) return new Fail("bad-txns-vout-negative", 100);
            if (o.value > ConsensusParams.MAX_MONEY) return new Fail("bad-txns-vout-toolarge", 100);
            total += o.value;
            if (total < 0 || total > ConsensusParams.MAX_MONEY) return new Fail("bad-txns-txouttotal-toolarge", 100);
            if (!addressValid(o.addrVersion, o.addrHash)) return new Fail("bad-txns-address-size", 100);
        }

        if (isCoinbase(tx)) {
            if (!isNullPrevout(tx.inputs.get(0))) return new Fail("bad-cb-outpoint", 100);
            if (witnessSize(tx.inputs.get(0).witness) > 1000) return new Fail("bad-cb-length", 100);
            for (int i = 1; i < tx.inputs.size(); i++) {
                TxParser.Input in = tx.inputs.get(i);
                if (!isNullPrevout(in)) return new Fail("bad-cb-outpoint", 100);
                if (in.witness.size() != 1) return new Fail("bad-cb-witness", 100);
                if (in.witness.get(0).length > 10000) return new Fail("bad-cb-length", 100);
            }
        } else {
            Set<String> seen = new HashSet<>();
            for (TxParser.Input in : tx.inputs) {
                if (!seen.add(hex(in.prevHash) + ":" + in.prevIndex)) return new Fail("bad-txns-inputs-duplicate", 100);
            }
            for (TxParser.Input in : tx.inputs) {
                if (isNullPrevout(in)) return new Fail("bad-txns-prevout-null", 10);
            }
        }

        if (!hasSaneCovenants(tx)) return new Fail("bad-txns-covenants", 100);
        return null;
    }

    // ── rules.hasSaneCovenants ───────────────────────────────────────────────

    private static boolean len(TxParser.Covenant c, int i, int n) { return item(c, i).length == n; }

    public static boolean hasSaneCovenants(TxParser.ParsedTx tx) {
        if (isCoinbase(tx)) {
            if (tx.inputs.size() > tx.outputs.size()) return false;
            for (int i = 0; i < tx.outputs.size(); i++) {
                TxParser.Covenant c = tx.outputs.get(i).covenant;
                switch (c.type) {
                    case NONE: {
                        if (!c.items.isEmpty()) return false;
                        if (i > 0 && i < tx.inputs.size()) {
                            if (tx.inputs.get(i).witness.size() != 1) return false;
                            // airdrop proof decode/sanity is not performed (see BlockValidator notes)
                        }
                        break;
                    }
                    case CLAIM: {
                        if (i == 0) return false;
                        if (i >= tx.inputs.size()) return false;
                        if (tx.inputs.get(i).witness.size() != 1) return false;
                        if (c.items.size() != 6) return false;
                        if (!len(c, 0, 32) || !len(c, 1, 4)) return false;
                        if (!HandshakeCovenantRules.verifyName(item(c, 2))) return false;
                        if (!len(c, 3, 1) || !len(c, 4, 32) || !len(c, 5, 4)) return false;
                        if (ReservedNames.get(item(c, 0)) == null) return false;
                        if (!Arrays.equals(hashName(item(c, 2)), item(c, 0))) return false;
                        break;
                    }
                    default:
                        return false;
                }
            }
            return true;
        }

        for (int i = 0; i < tx.outputs.size(); i++) {
            TxParser.Covenant c = tx.outputs.get(i).covenant;
            switch (c.type) {
                case NONE:
                    if (!c.items.isEmpty()) return false;
                    break;
                case CLAIM:
                    return false;
                case OPEN: {
                    if (c.items.size() != 3) return false;
                    if (!len(c, 0, 32) || !len(c, 1, 4)) return false;
                    if (getU32(c, 1) != 0) return false;
                    if (!HandshakeCovenantRules.verifyName(item(c, 2))) return false;
                    if (!Arrays.equals(hashName(item(c, 2)), item(c, 0))) return false;
                    break;
                }
                case BID: {
                    if (c.items.size() != 4) return false;
                    if (!len(c, 0, 32) || !len(c, 1, 4)) return false;
                    if (!HandshakeCovenantRules.verifyName(item(c, 2))) return false;
                    if (!len(c, 3, 32)) return false;
                    if (!Arrays.equals(hashName(item(c, 2)), item(c, 0))) return false;
                    break;
                }
                case REVEAL:
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 3 || !len(c, 0, 32) || !len(c, 1, 4) || !len(c, 2, 32)) return false;
                    break;
                case REDEEM:
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 2 || !len(c, 0, 32) || !len(c, 1, 4)) return false;
                    break;
                case REGISTER:
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 4 || !len(c, 0, 32) || !len(c, 1, 4)) return false;
                    if (item(c, 2).length > ConsensusParams.MAX_RESOURCE_SIZE) return false;
                    if (!len(c, 3, 32)) return false;
                    break;
                case UPDATE:
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 3 || !len(c, 0, 32) || !len(c, 1, 4)) return false;
                    if (item(c, 2).length > ConsensusParams.MAX_RESOURCE_SIZE) return false;
                    break;
                case RENEW:
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 3 || !len(c, 0, 32) || !len(c, 1, 4) || !len(c, 2, 32)) return false;
                    break;
                case TRANSFER: {
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 4 || !len(c, 0, 32) || !len(c, 1, 4) || !len(c, 2, 1)) return false;
                    int version = getU8(c, 2);
                    int hl = item(c, 3).length;
                    if (version > 31) return false;
                    if (hl < 2 || hl > 40) return false;
                    break;
                }
                case FINALIZE: {
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 7 || !len(c, 0, 32) || !len(c, 1, 4)) return false;
                    if (!HandshakeCovenantRules.verifyName(item(c, 2))) return false;
                    if (!len(c, 3, 1) || !len(c, 4, 4) || !len(c, 5, 4) || !len(c, 6, 32)) return false;
                    if (!Arrays.equals(hashName(item(c, 2)), item(c, 0))) return false;
                    break;
                }
                case REVOKE:
                    if (i >= tx.inputs.size()) return false;
                    if (c.items.size() != 2 || !len(c, 0, 32) || !len(c, 1, 4)) return false;
                    break;
                default: {
                    if (c.items.size() > 1000) return false;
                    int size = 0;
                    for (TxParser.CovenantItem it : c.items) {
                        int l = it.data == null ? 0 : it.data.length;
                        size += BlockTemplates.varintSize(l) + l;
                    }
                    if (size > ConsensusParams.MAX_COVENANT_SIZE) return false;
                    break;
                }
            }
        }
        return true;
    }

    // ── tx.isFinal ───────────────────────────────────────────────────────────

    public static boolean isFinal(TxParser.ParsedTx tx, int height, long mtp) {
        return BlockTemplates.isFinal(tx, height, mtp);
    }

    // ── rules.verifyCovenants (input/output covenant links; non-coinbase) ────

    /** Returns false when the tx violates covenant linkage (hsd returns -1 => bad-txns-covenants). */
    public static boolean verifyCovenantLinks(TxParser.ParsedTx tx, List<ChainDB.UtxoEntry> coins) {
        for (int i = 0; i < tx.inputs.size(); i++) {
            ChainDB.UtxoEntry coin = coins.get(i);
            TxParser.Covenant uc = decodeCovenant(coin.covenantType(), coin.covenantData());
            TxParser.Output output = i < tx.outputs.size() ? tx.outputs.get(i) : null;
            TxParser.Covenant cov = output != null ? output.covenant : null;

            switch (uc.type) {
                case NONE: case OPEN: case REDEEM: {
                    if (output == null) break;
                    switch (cov.type) {
                        case NONE: case OPEN: case BID: break;
                        default: return false;
                    }
                    break;
                }
                case BID: {
                    if (output == null) return false;
                    if (cov.type != REVEAL) return false;
                    if (!Arrays.equals(getHash(cov, 0), getHash(uc, 0))) return false;
                    if (getU32(cov, 1) != getU32(uc, 1)) return false;
                    byte[] nonce = getHash(cov, 2);
                    byte[] blind = blind(output.value, nonce);
                    if (!Arrays.equals(blind, getHash(uc, 3))) return false;
                    if (coin.value() < output.value) return false;
                    break;
                }
                case CLAIM: case REVEAL: {
                    if (output == null) return false;
                    switch (cov.type) {
                        case REGISTER: {
                            if (!Arrays.equals(getHash(cov, 0), getHash(uc, 0))) return false;
                            if (getU32(cov, 1) != getU32(uc, 1)) return false;
                            if (!sameAddress(output, coin)) return false;
                            break;
                        }
                        case REDEEM: {
                            if (!Arrays.equals(getHash(cov, 0), getHash(uc, 0))) return false;
                            if (getU32(cov, 1) != getU32(uc, 1)) return false;
                            if (uc.type == CLAIM) return false;
                            break;
                        }
                        default: return false;
                    }
                    break;
                }
                case REGISTER: case UPDATE: case RENEW: case FINALIZE: {
                    if (output == null) return false;
                    if (output.value != coin.value()) return false;
                    if (!sameAddress(output, coin)) return false;
                    switch (cov.type) {
                        case UPDATE: case RENEW: case TRANSFER: case REVOKE: {
                            if (!Arrays.equals(getHash(cov, 0), getHash(uc, 0))) return false;
                            if (getU32(cov, 1) != getU32(uc, 1)) return false;
                            break;
                        }
                        default: return false;
                    }
                    break;
                }
                case TRANSFER: {
                    if (output == null) return false;
                    if (output.value != coin.value()) return false;
                    switch (cov.type) {
                        case UPDATE: case RENEW: case REVOKE: {
                            if (!Arrays.equals(getHash(cov, 0), getHash(uc, 0))) return false;
                            if (getU32(cov, 1) != getU32(uc, 1)) return false;
                            if (!sameAddress(output, coin)) return false;
                            break;
                        }
                        case FINALIZE: {
                            if (!Arrays.equals(getHash(cov, 0), getHash(uc, 0))) return false;
                            if (getU32(cov, 1) != getU32(uc, 1)) return false;
                            if (output.addrVersion != getU8(uc, 2)) return false;
                            if (!Arrays.equals(output.addrHash, item(uc, 3))) return false;
                            break;
                        }
                        default: return false;
                    }
                    break;
                }
                case REVOKE:
                    return false;
                default: {
                    if (output != null && isName(cov.type)) return false;
                    break;
                }
            }
        }
        return true;
    }

    private static boolean sameAddress(TxParser.Output o, ChainDB.UtxoEntry c) {
        return o.addrVersion == c.addrVersion() && Arrays.equals(o.addrHash, c.addrHash());
    }

    static String hex(byte[] b) { return handshake.node.util.HexUtil.encode(b); }
}