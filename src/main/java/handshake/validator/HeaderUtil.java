package handshake.validator;

import java.math.BigInteger;

/**
 * Utilities for parsing the 236-byte Handshake block header format.
    * <p>
 * Field order confirmed against a real, dedicated implementation
 * ("hns_header_consensus", documented as "Canonical 236-byte Handshake
 * headers and proof-of-work consensus") -- its encode() method writes
 * fields in this exact order, all little-endian:
    * <p>
 *   nonce(4) + time(8) + prevBlock(32) + treeRoot(32) + extraNonce(24)
 *   + reservedRoot(32) + witnessRoot(32) + merkleRoot(32) + version(4)
 *   + bits(4) + mask(32) = 236 bytes
    * <p>
 * This directly contradicts an earlier assumption elsewhere in this
 * codebase (RpcServer previously read "time" from offset 100 and
 * "version" as if it were the first field) -- those were wrong and are
 * fixed to use these confirmed offsets.
    * <p>
 * The block hash uses Handshake's real "share hash" scheme -- a
 * deliberately expensive, ASIC-resistant construction involving Blake2b
 * at two different output sizes, SHA3-256, and an XOR mask -- NOT a
 * simple Blake2b(header). This was discovered directly from real hsd
 * source (lib/primitives/abstractblock.js's hash()/powHash()/shareHash()
 * chain) after an earlier, much simpler implementation here turned out
 * to be wrong: it was internally self-consistent (a hardcoded genesis
 * constant derived the same way matched it), but never actually matched
 * what real hsd peers consider "the hash of a block," which is why no
 * peer ever recognized our GETHEADERS locator no matter what else got
 * fixed along the way.
 */
public class HeaderUtil {

    public static final int OFF_NONCE     = 0;
    public static final int OFF_TIME      = 4;
    public static final int OFF_PREVBLOCK = 12;
    public static final int OFF_TREEROOT  = 44;
    public static final int OFF_EXTRANONCE = 76;
    public static final int OFF_RESERVEDROOT = 100;
    public static final int OFF_WITNESSROOT  = 132;
    public static final int OFF_MERKLEROOT   = 164;
    public static final int OFF_VERSION      = 196;
    public static final int OFF_BITS         = 200;
    public static final int OFF_MASK         = 204;
    public static final int HEADER_SIZE      = 236;

    public static byte[] prevBlock(byte[] header) {
        return java.util.Arrays.copyOfRange(header, OFF_PREVBLOCK, OFF_PREVBLOCK + 32);
    }

    public static byte[] treeRoot(byte[] header) {
        return java.util.Arrays.copyOfRange(header, OFF_TREEROOT, OFF_TREEROOT + 32);
    }

    public static byte[] extraNonce(byte[] header) {
        return java.util.Arrays.copyOfRange(header, OFF_EXTRANONCE, OFF_EXTRANONCE + 24);
    }

    public static byte[] reservedRoot(byte[] header) {
        return java.util.Arrays.copyOfRange(header, OFF_RESERVEDROOT, OFF_RESERVEDROOT + 32);
    }

    public static byte[] witnessRoot(byte[] header) {
        return java.util.Arrays.copyOfRange(header, OFF_WITNESSROOT, OFF_WITNESSROOT + 32);
    }

    public static byte[] merkleRoot(byte[] header) {
        return java.util.Arrays.copyOfRange(header, OFF_MERKLEROOT, OFF_MERKLEROOT + 32);
    }

    public static byte[] mask(byte[] header) {
        return java.util.Arrays.copyOfRange(header, OFF_MASK, OFF_MASK + 32);
    }

    public static long nonce(byte[] header) {
        return readLE32(header, OFF_NONCE);
    }

    public static long time(byte[] header) {
        return readLE64(header, OFF_TIME);
    }

    public static int bits(byte[] header) {
        return (int) readLE32(header, OFF_BITS);
    }

    public static int version(byte[] header) {
        return (int) readLE32(header, OFF_VERSION);
    }

    /**
     * Deterministic pseudo-random padding: pad[i] = prevBlock[i%32] XOR
     * treeRoot[i%32]. Matches abstractblock.js's padding(size) exactly.
     */
    private static byte[] padding(byte[] header, int size) {
        byte[] prev = prevBlock(header);
        byte[] tree = treeRoot(header);
        byte[] pad = new byte[size];
        for (int i = 0; i < size; i++) {
            pad[i] = (byte) (prev[i % 32] ^ tree[i % 32]);
        }
        return pad;
    }

    /**
     * Subheader: extraNonce(24) + reservedRoot(32) + witnessRoot(32) +
     * merkleRoot(32) + version(4 LE) + bits(4 LE) = exactly 128 bytes
     * (one Blake2b block). Matches toSubhead() exactly.
     */
    private static byte[] toSubhead(byte[] header) {
        byte[] buf = new byte[128];
        int pos = 0;
        System.arraycopy(extraNonce(header), 0, buf, pos, 24); pos += 24;
        System.arraycopy(reservedRoot(header), 0, buf, pos, 32); pos += 32;
        System.arraycopy(witnessRoot(header), 0, buf, pos, 32); pos += 32;
        System.arraycopy(merkleRoot(header), 0, buf, pos, 32); pos += 32;
        writeLE32(buf, pos, version(header)); pos += 4;
        writeLE32(buf, pos, bits(header)); pos += 4;
        return buf;
    }

    private static byte[] subHash(byte[] header) {
        return Blake2b.hash(toSubhead(header), 32);
    }

    /** Blake2b-256(prevBlock || mask). Matches maskHash() exactly. */
    private static byte[] maskHash(byte[] header) {
        return Blake2b.hash(concat(prevBlock(header), mask(header)), 32);
    }

    /** Blake2b-256(subHash || maskHash). Matches commitHash() exactly. */
    private static byte[] commitHash(byte[] header) {
        return Blake2b.hash(concat(subHash(header), maskHash(header)), 32);
    }

    /**
     * Preheader: nonce(4 LE) + time(8 LE) + padding(20) + prevBlock(32) +
     * treeRoot(32) + commitHash(32) = exactly 128 bytes (one Blake2b
     * block). Matches toPrehead() exactly.
     */
    private static byte[] toPrehead(byte[] header) {
        byte[] buf = new byte[128];
        int pos = 0;
        writeLE32(buf, pos, (int) nonce(header)); pos += 4;
        writeLE64(buf, pos, time(header)); pos += 8;
        System.arraycopy(padding(header, 20), 0, buf, pos, 20); pos += 20;
        System.arraycopy(prevBlock(header), 0, buf, pos, 32); pos += 32;
        System.arraycopy(treeRoot(header), 0, buf, pos, 32); pos += 32;
        System.arraycopy(commitHash(header), 0, buf, pos, 32); pos += 32;
        return buf;
    }

    /**
     * The real "share hash" -- Handshake's deliberately expensive,
     * mask-based ASIC-resistance scheme. Matches shareHash() exactly:
     *   data = toPrehead()                          (128 bytes)
     *   left = Blake2b-512(data)                     (64 bytes)
     *   right = SHA3-256(data || padding(8))          (32 bytes)
     *   result = Blake2b-256(left || padding(32) || right)
     */
    private static byte[] shareHash(byte[] header) {
        byte[] data = toPrehead(header);
        byte[] left = Blake2b.hash(data, 64);
        byte[] right = sha3_256(concat(data, padding(header, 8)));
        byte[] combined = concat(concat(left, padding(header, 32)), right);
        return Blake2b.hash(combined, 32);
    }

    /**
     * The REAL block hash: shareHash() XOR mask, byte-wise over the
     * first 32 bytes. Matches powHash() exactly. This REPLACES a much
     * earlier, incorrect implementation that just did Blake2b(header) --
     * confirmed wrong via direct comparison against a real hsd peer's
     * response: the decoded first-item hash never matched what
     * Blake2b(header) produced, only what this full algorithm produces.
     * That earlier version was self-consistent (matched a hardcoded
     * constant derived the same wrong way) but never actually matched
     * what real hsd considers "the hash of a block" -- explaining why no
     * real peer ever recognized our GETHEADERS locator no matter how
     * many other things got fixed.
     */
    public static byte[] hash(byte[] header) {
        byte[] shareHash = shareHash(header);
        byte[] mask = mask(header);
        byte[] result = shareHash.clone();
        for (int i = 0; i < 32; i++) {
            result[i] ^= mask[i];
        }
        return result;
    }

    /**
     * Verifies that a header's hash actually satisfies the difficulty
     * target encoded in its own "bits" field -- the fundamental defense
     * against a malicious or compromised peer fabricating headers. Chain-
     * link validation alone (prevBlock references) only proves headers
     * were CONSTRUCTED to reference each other; it says nothing about
     * whether they represent genuine, expensive-to-fake proof-of-work.
     * Fabricating a long, correctly-chaining but low/no-difficulty header
     * sequence is trivial; fabricating one that also satisfies real
     * mainnet difficulty at every step is not, which is exactly the
     * property that makes this check meaningful.
        * <p>
     * Target decoding matches Bitcoin/hsd's standard compact ("nBits")
     * encoding: top byte = exponent, next bit = sign, low 23 bits =
     * mantissa. hash(header), interpreted as a big-endian unsigned
     * integer, must be <= target.
     */
    public static boolean checkPOW(byte[] header) {
        BigInteger target = fromCompact(bits(header));
        if (target.signum() <= 0 || target.bitLength() > 256) return false;
        BigInteger hashInt = new BigInteger(1, hash(header));
        return hashInt.compareTo(target) <= 0;
    }

    private static BigInteger fromCompact(int compact) {
        int exponent = (compact >>> 24) & 0xFF;
        int negative = (compact >>> 23) & 0x01;
        long mantissa = compact & 0x7FFFFFL;

        if (mantissa == 0) return BigInteger.ZERO;

        BigInteger target;
        if (exponent <= 3) {
            mantissa >>= 8 * (3 - exponent);
            target = BigInteger.valueOf(mantissa);
        } else {
            target = BigInteger.valueOf(mantissa).shiftLeft(8 * (exponent - 3));
        }
        if (negative != 0) target = target.negate();
        return target;
    }

    /** Public for reuse elsewhere (e.g. scripthash address generation,
     *  which real hsd's Address.fromScript() also computes via SHA3-256,
     *  confirmed directly from address.js -- not Blake2b, unlike pubkey
     *  hashing). */
    public static byte[] sha3_256(byte[] data) {
        try {
            return java.security.MessageDigest.getInstance("SHA3-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static void writeLE32(byte[] buf, int pos, int v) {
        buf[pos] = (byte) v; buf[pos+1] = (byte) (v >>> 8);
        buf[pos+2] = (byte) (v >>> 16); buf[pos+3] = (byte) (v >>> 24);
    }

    private static void writeLE64(byte[] buf, int pos, long v) {
        for (int i = 0; i < 8; i++) buf[pos+i] = (byte) (v >>> (i * 8));
    }

    /**
     * Checks that header's prevBlock field correctly references the
     * previous header's hash -- the fundamental chain-linking check.
     */
    public static boolean chainsFrom(byte[] header, byte[] previousHeader) {
        if (header == null || previousHeader == null) return false;
        byte[] expectedPrev = hash(previousHeader);
        byte[] actualPrev = prevBlock(header);
        return java.util.Arrays.equals(expectedPrev, actualPrev);
    }

    private static long readLE32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off+1] & 0xFFL) << 8)
                | ((b[off+2] & 0xFFL) << 16) | ((b[off+3] & 0xFFL) << 24);
    }

    private static long readLE64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v |= (b[off+i] & 0xFFL) << (i * 8);
        return v;
    }
}