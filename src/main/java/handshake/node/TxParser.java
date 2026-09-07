package handshake.node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TxParser — lightweight parser for Handshake raw transactions.
    * <p>
 * Handshake transaction wire format:
 *   version    (4 bytes LE)
 *   input_count (varint)
 *   inputs[]   each: prevhash(32) + previndex(4) + sequence(4)
 *   output_count (varint)
 *   outputs[]  each: value(8) + addr_version(1) + addr_hash_len(1)
 *              + addr_hash(N) + covenant_type(1) + covenant_items_count(varint)
 *              + covenant_items[] each: item_len(varint) + item_data(N)
 *   locktime   (4 bytes LE)
 *   witnesses  (not included in base transaction for txid computation)
    * <p>
 * The "base" transaction (used for txid) excludes witness data.
 * Witness data follows the locktime in the full transaction.
 */
public class TxParser {

    // ── Parsed structures ─────────────────────────────────────────────────────

    public static class Input {
        public byte[] prevHash;    // raw wire-order bytes (32), needed for sighash
        public String prevTxid;    // display format (reversed bytes)
        public int    prevIndex;
        public int    sequence;
        public List<byte[]> witness = new ArrayList<>(); // stack items, e.g. [sig, pubkey]

        public boolean isCoinbase() {
            // Coinbase input: prevTxid is all zeros, prevIndex is 0xFFFFFFFF
            return prevTxid.equals("0000000000000000000000000000000000000000000000000000000000000000")
                    && prevIndex == 0xFFFFFFFF;
        }
    }

    public static class CovenantItem {
        public byte[] data;
    }

    public static class Covenant {
        public int type;
        public List<CovenantItem> items = new ArrayList<>();
    }

    public static class Output {
        public long     value;
        public int      addrVersion;
        public byte[]   addrHash;
        public Covenant covenant;
    }

    public static class ParsedTx {
        public int         version;
        public List<Input>  inputs  = new ArrayList<>();
        public List<Output> outputs = new ArrayList<>();
        public int         locktime;
        public int         baseSize;  // size of base tx (no witnesses)
        public int         totalSize; // full size INCLUDING witness data
        public byte[]      raw;
    }

    // ── Covenant types ────────────────────────────────────────────────────────

    public static final int COV_NONE     = 0;
    public static final int COV_CLAIM    = 1;
    public static final int COV_OPEN     = 2;
    public static final int COV_BID      = 3;
    public static final int COV_REVEAL   = 4;
    public static final int COV_REDEEM   = 5;
    public static final int COV_REGISTER = 6;
    public static final int COV_UPDATE   = 7;
    public static final int COV_RENEW    = 8;
    public static final int COV_TRANSFER = 9;
    public static final int COV_FINALIZE = 10;
    public static final int COV_REVOKE   = 11;

    // ── Parser ────────────────────────────────────────────────────────────────

    /**
     * Parses a raw Handshake transaction.
     * Returns null if parsing fails.
     */
    public static ParsedTx parse(byte[] raw) {
        try {
            Parser p = new Parser(raw);
            ParsedTx tx = new ParsedTx();
            tx.raw = raw;

            // Version
            tx.version = (int) p.readLE32();

            // Inputs
            int inputCount = (int) p.readVarint();
            for (int i = 0; i < inputCount; i++) {
                Input in = new Input();
                byte[] prevHash = p.readBytes(32);
                in.prevHash  = prevHash;
                // Store as display format (reversed)
                in.prevTxid  = hexReversed(prevHash);
                in.prevIndex = (int) p.readLE32();
                in.sequence  = (int) p.readLE32();
                tx.inputs.add(in);
            }

            // Outputs
            int outputCount = (int) p.readVarint();
            for (int i = 0; i < outputCount; i++) {
                Output out = new Output();
                out.value       = p.readLE64();
                out.addrVersion = p.readByte();
                int hashLen     = p.readByte();
                out.addrHash    = p.readBytes(hashLen);

                // Covenant
                Covenant cov  = new Covenant();
                cov.type      = p.readByte();
                int itemCount = (int) p.readVarint();
                for (int j = 0; j < itemCount; j++) {
                    CovenantItem item = new CovenantItem();
                    int itemLen = (int) p.readVarint();
                    item.data   = p.readBytes(itemLen);
                    cov.items.add(item);
                }
                out.covenant = cov;
                tx.outputs.add(out);
            }

            // Locktime
            tx.locktime  = (int) p.readLE32();
            tx.baseSize  = p.position(); // base tx ends here

            // Witness data: one witness stack per INPUT. Confirmed against
            // real captured transactions: per input, itemCount(varint)
            // followed by itemCount items, each itemLen(varint) + bytes.
            // This was previously missing entirely -- parse() stopped
            // right after locktime, and a separate, unrelated function
            // GUESSED each transaction's total size as "baseSize + 150
            // bytes per input" rather than actually reading the real
            // witness data, silently misaligning every transaction after
            // any one whose witness data didn't happen to match that
            // guess -- which is effectively all of them with real
            // signatures, explaining why every block's merkle root was
            // wrong despite the merkle algorithm and txid computation
            // both being individually correct.
            //
            // Now actually STORED (not just walked for size) -- needed
            // for mempool signature verification, which needs the real
            // signature+pubkey bytes, not just to know where they end.
            for (int i = 0; i < tx.inputs.size(); i++) {
                Input in = tx.inputs.get(i);
                int itemCount = (int) p.readVarint();
                for (int j = 0; j < itemCount; j++) {
                    int itemLen = (int) p.readVarint();
                    in.witness.add(p.readBytes(itemLen));
                }
            }
            tx.totalSize = p.position();

            return tx;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Computes the txid (Blake2b-256 of base transaction).
     * Returns hex string in display format.
     */
    public static String computeTxid(byte[] raw) {
        ParsedTx tx = parse(raw);
        if (tx == null) return null;
        byte[] base = Arrays.copyOf(raw, tx.baseSize);
        return hex(Blake2b.hash256(base));
    }

    /**
     * Returns the name hash from a covenant output (item[0]).
     * Returns null if no name hash is present.
     */
    public static byte[] getNameHash(Output output) {
        if (output.covenant == null) return null;
        if (output.covenant.items.isEmpty()) return null;
        return output.covenant.items.get(0).data;
    }

    /**
     * Returns the name bytes from a covenant output (item[2] for most types).
     */
    public static byte[] getNameBytes(Output output) {
        if (output.covenant == null) return null;
        List<CovenantItem> items = output.covenant.items;
        switch (output.covenant.type) {
            case COV_OPEN:
            case COV_BID:
            case COV_REGISTER:
            case COV_UPDATE:
            case COV_RENEW:
            case COV_TRANSFER:
            case COV_FINALIZE:
            case COV_REVOKE:
                return items.size() > 2 ? items.get(2).data : null;
            default:
                return null;
        }
    }

    // ── Internal parser ───────────────────────────────────────────────────────

    private static class Parser {
        private final byte[] data;
        private int pos;

        Parser(byte[] data) {
            this.data = data;
            this.pos  = 0;
        }

        int position() { return pos; }

        int readByte() {
            return data[pos++] & 0xFF;
        }

        byte[] readBytes(int len) {
            byte[] b = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            return b;
        }

        /** Reads exactly 2 bytes as a little-endian unsigned 16-bit value.
         *  Needed for the 0xFD-prefixed varint case, which is 1 prefix
         *  byte + 2 value bytes (3 bytes total) -- NOT 1 + 4. Previously
         *  readVarint() called readLE32() for this case, which correctly
         *  computed the value from the first 2 bytes via a "& 0xFFFF"
         *  mask, but incorrectly advanced the position by 4 bytes instead
         *  of 2 -- silently overreading by 2 bytes and misaligning every
         *  subsequent read for the rest of that transaction. This only
         *  ever surfaced for transactions with 253 or more inputs,
         *  outputs, or witness items (anything requiring a multi-byte
         *  varint), which is why it stayed hidden through extensive
         *  testing of smaller, more typical transactions and only showed
         *  up as sporadic, hard-to-reproduce merkle root mismatches. */
        int readLE16() {
            int v = (data[pos] & 0xFF) | ((data[pos+1] & 0xFF) << 8);
            pos += 2;
            return v;
        }

        long readLE32() {
            long v = (data[pos] & 0xFFL)
                    | ((data[pos+1] & 0xFFL) << 8)
                    | ((data[pos+2] & 0xFFL) << 16)
                    | ((data[pos+3] & 0xFFL) << 24);
            pos += 4;
            return v;
        }

        long readLE64() {
            long v = (data[pos] & 0xFFL)
                    | ((data[pos+1] & 0xFFL) << 8)
                    | ((data[pos+2] & 0xFFL) << 16)
                    | ((data[pos+3] & 0xFFL) << 24)
                    | ((data[pos+4] & 0xFFL) << 32)
                    | ((data[pos+5] & 0xFFL) << 40)
                    | ((data[pos+6] & 0xFFL) << 48)
                    | ((data[pos+7] & 0xFFL) << 56);
            pos += 8;
            return v;
        }

        long readVarint() {
            int first = readByte();
            if (first < 0xFD) return first;
            if (first == 0xFD) return readLE16();
            if (first == 0xFE) return readLE32();
            // 0xFF: 8-byte varint
            return readLE64();
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** Reverses byte order and returns hex — converts wire format to display format. */
    private static String hexReversed(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (int i = b.length - 1; i >= 0; i--)
            sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }
}