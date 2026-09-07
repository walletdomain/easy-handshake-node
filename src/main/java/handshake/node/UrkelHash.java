package handshake.node;

/**
 * The domain-separated hash constructions from real Urkel's common.js,
 * translated directly from the actual source. A single leading byte
 * distinguishes node types before hashing -- 0x00=leaf, 0x01=internal
 * with no compressed prefix, 0x02=internal with one -- confirmed
 * directly from source, not guessed. Uses this project's own
 * Blake2b.hash(), since real Urkel's "hash.multi(a, b, c)" is exactly
 * "concatenate these byte strings, then hash the result" -- mathematically
 * identical to concatenating first and calling a single hash, which is
 * what a well-behaved cryptographic hash's streaming/update API always
 * reduces to.
 */
public final class UrkelHash {

    private UrkelHash() {}

    public static final int HASH_SIZE = 32; // BLAKE2b-256

    /** The hash of an empty/Null subtree -- a constant, all-zero value
     *  of the hash's own output size, matching real Urkel's "hash.zero"
     *  convention. */
    public static final byte[] ZERO = new byte[HASH_SIZE];

    private static final byte LEAF_PREFIX = 0x00;
    private static final byte INTERNAL_PREFIX = 0x01;
    private static final byte SKIP_PREFIX = 0x02;

    public static byte[] hashInternal(UrkelBits prefix, byte[] left, byte[] right) {
        if (prefix.size == 0) {
            byte[] combined = new byte[1 + left.length + right.length];
            combined[0] = INTERNAL_PREFIX;
            System.arraycopy(left, 0, combined, 1, left.length);
            System.arraycopy(right, 0, combined, 1 + left.length, right.length);
            return Blake2b.hash(combined, HASH_SIZE);
        }

        // 0x02 || u16LE(prefix.size) || prefix.data || left || right
        byte[] combined = new byte[1 + 2 + prefix.data.length + left.length + right.length];
        int pos = 0;
        combined[pos++] = SKIP_PREFIX;
        combined[pos++] = (byte) (prefix.size & 0xFF);         // LE low byte
        combined[pos++] = (byte) ((prefix.size >>> 8) & 0xFF); // LE high byte
        System.arraycopy(prefix.data, 0, combined, pos, prefix.data.length);
        pos += prefix.data.length;
        System.arraycopy(left, 0, combined, pos, left.length);
        pos += left.length;
        System.arraycopy(right, 0, combined, pos, right.length);
        return Blake2b.hash(combined, HASH_SIZE);
    }

    public static byte[] hashLeaf(byte[] key, byte[] valueHash) {
        byte[] combined = new byte[1 + key.length + valueHash.length];
        combined[0] = LEAF_PREFIX;
        System.arraycopy(key, 0, combined, 1, key.length);
        System.arraycopy(valueHash, 0, combined, 1 + key.length, valueHash.length);
        return Blake2b.hash(combined, HASH_SIZE);
    }

    public static byte[] hashValue(byte[] key, byte[] value) {
        byte[] valueHash = Blake2b.hash(value, HASH_SIZE);
        return hashLeaf(key, valueHash);
    }
}