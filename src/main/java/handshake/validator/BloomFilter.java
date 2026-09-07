package handshake.validator;

/**
 * A BIP37-style Bloom filter: N independent "hash functions" are all
 * really the same MurmurHash3, just seeded differently per BIP 0037's
 * own scheme (seed = hashNum * 0xFBA4C795 + tweak) -- a well-documented,
 * standard, non-Handshake-specific construction.
 *
 * The wire *serialization* of a filter is deliberately NOT modeled on
 * Bitcoin/hsd's own undocumented-here binary buffer format (their
 * filterload message payload) -- this project's socket protocol is
 * JSON end to end already (see NodeSocketServer), so filters are sent
 * as {"data":"<hex>","hashFuncs":N,"tweak":N} instead of trying to
 * replicate an exact binary layout with no verified source at hand.
 * The underlying matching algorithm (which is the part that actually
 * needs to be standard for correctness) is the real, verified BIP37
 * scheme either way.
 */
public class BloomFilter {

    private final byte[] data;
    private final int hashFuncs;
    private final int tweak;

    public BloomFilter(byte[] data, int hashFuncs, int tweak) {
        if (data.length == 0) throw new IllegalArgumentException("Bloom filter data cannot be empty");
        if (hashFuncs <= 0 || hashFuncs > 50)
            throw new IllegalArgumentException("hashFuncs out of reasonable range: " + hashFuncs);
        this.data = data;
        this.hashFuncs = hashFuncs;
        this.tweak = tweak;
    }

    /** Sets the bits corresponding to this element -- BIP37's "add". */
    public void add(byte[] element) {
        for (int i = 0; i < hashFuncs; i++) {
            int idx = hashIndex(element, i);
            data[idx / 8] |= (byte) (1 << (idx % 8));
        }
    }

    /** True if this element *might* be in the filter (Bloom filters can
     *  false-positive by design, but never false-negative: if this
     *  returns false, the element was definitely never added). */
    public boolean contains(byte[] element) {
        for (int i = 0; i < hashFuncs; i++) {
            int idx = hashIndex(element, i);
            if ((data[idx / 8] & (1 << (idx % 8))) == 0) return false;
        }
        return true;
    }

    private int hashIndex(byte[] element, int hashNum) {
        int seed = hashNum * 0xFBA4C795 + tweak;
        int hash = MurmurHash3.hash(element, seed);
        // Unsigned modulo against the bit-length of the filter, matching
        // BIP37's own "% (filter.length * 8)" -- Java's % is signed, so
        // Integer.remainderUnsigned is needed since MurmurHash3's output
        // is used as an unsigned 32-bit value in the reference scheme.
        long bitLength = (long) data.length * 8;
        return (int) (Integer.toUnsignedLong(hash) % bitLength);
    }
}