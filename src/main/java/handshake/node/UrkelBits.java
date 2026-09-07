package handshake.node;

/**
 * A compressed bit-prefix, exactly matching real Urkel's bits.js --
 * translated directly from the actual handshake-org/urkel source
 * (uploaded and read in full), not guessed at. This is the piece that
 * makes Urkel a real Patricia/Merklix-style radix tree rather than a
 * plain bit-by-bit binary trie: an Internal node's "prefix" is exactly
 * this structure, representing zero or more bits that got compressed
 * together on the path to that node.
 *
 * Bit ordering is MSB-first within each byte (bit 0 = the most
 * significant bit of byte 0), matching common.js's hasBit/setBit
 * exactly -- confirmed directly from source, not assumed.
 */
public final class UrkelBits {

    public static final UrkelBits EMPTY = new UrkelBits();

    public int size;
    public byte[] data;

    public UrkelBits() {
        this.size = 0;
        this.data = new byte[0];
    }

    private UrkelBits(int size, byte[] data) {
        this.size = size;
        this.data = data;
    }

    /** MSB-first bit read, matching common.js's hasBit exactly. */
    public static boolean hasBit(byte[] key, int index) {
        int oct = index >>> 3;
        int bit = index & 7;
        return ((key[oct] & 0xFF) >>> (7 - bit) & 1) == 1;
    }

    /** MSB-first bit set (OR-in), matching common.js's setBit exactly. */
    public static void setBit(byte[] key, int index, boolean b) {
        int oct = index >>> 3;
        int bit = index & 7;
        if (b) key[oct] |= (byte) (1 << (7 - bit));
    }

    public UrkelBits clone() {
        if (size == 0) return this;
        return new UrkelBits(size, data.clone());
    }

    public boolean get(int index) {
        return hasBit(data, index);
    }

    public void set(int index, boolean bit) {
        setBit(data, index, bit);
    }

    /** True if this Bits' entire content matches `key` starting at
     *  `depth` (i.e. the full prefix is consumed with no mismatch). */
    public boolean has(byte[] key, int depth) {
        return count(key, depth) == size;
    }

    /** How many of this Bits' bits (starting at bit 0) match `key`
     *  (starting at bit `depth`), stopping at the first mismatch or
     *  whichever of the two runs out first. */
    public int count(byte[] key, int depth) {
        return countFrom(0, key, depth);
    }

    private int countFrom(int index, byte[] key, int depth) {
        int x = size - index;
        int y = (key.length * 8) - depth;
        int len = Math.min(x, y);

        int bits = 0;
        for (int i = 0; i < len; i++) {
            if (get(index) != hasBit(key, depth)) break;
            index += 1;
            depth += 1;
            bits += 1;
        }
        return bits;
    }

    /** Extracts bits [start, end) as a new, independently-allocated
     *  Bits. */
    public UrkelBits slice(int start, int end) {
        int size = end - start;
        if (size == 0) return EMPTY;

        UrkelBits bits = alloc(size);
        for (int i = start, j = 0; i < end; i++, j++) {
            bits.set(j, get(i));
        }
        return bits;
    }

    /** Splits at `index`, deliberately DROPPING the bit at that exact
     *  position -- that bit becomes the left/right branch choice at
     *  the new Internal node created around this split, so it must
     *  not also be duplicated inside either resulting prefix. Matches
     *  bits.js's split() exactly, including this gap. */
    public UrkelBits[] split(int index) {
        return new UrkelBits[] { slice(0, index), slice(index + 1, size) };
    }

    /** Used by a Leaf (whose "bits" is its entire key treated as a
     *  256-bit -- or however many bits -- Bits object) to find how
     *  many further bits it shares with a new, different key, starting
     *  from a depth both already matched up to. */
    public UrkelBits collide(byte[] key, int depth) {
        int size = countFrom(depth, key, depth);
        return slice(depth, depth + size);
    }

    /** Rejoins a parent prefix + a connecting bit + a child prefix into
     *  one combined prefix -- used when removing a leaf collapses an
     *  Internal node that's no longer needed. */
    public UrkelBits join(UrkelBits bits, boolean bit) {
        int size = this.size + bits.size + 1;
        UrkelBits out = alloc(size);

        System.arraycopy(this.data, 0, out.data, 0, this.data.length);
        out.set(this.size, bit);

        for (int i = 0, j = this.size + 1; i < bits.size; i++, j++) {
            out.set(j, bits.get(i));
        }
        return out;
    }

    public static UrkelBits alloc(int size) {
        UrkelBits b = new UrkelBits();
        b.size = size;
        b.data = new byte[(size + 7) >>> 3];
        return b;
    }

    /** Treats an entire byte array as a Bits object covering all of its
     *  bits -- used for a Leaf's own key (Leaf.bits in nodes.js). */
    public static UrkelBits from(byte[] data) {
        UrkelBits b = new UrkelBits();
        b.size = data.length * 8;
        b.data = data;
        return b;
    }

    /** Simple "0101..." string form, matching bits.js's toString/
     *  fromString -- used for this project's own JSON proof
     *  serialization rather than urkel's binary wire format, which
     *  isn't needed here (this project's protocols are JSON end to
     *  end already, same reasoning as everywhere else). */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; i++) sb.append(get(i) ? '1' : '0');
        return sb.toString();
    }

    public static UrkelBits fromString(String str) {
        UrkelBits b = alloc(str.length());
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            if (ch != '0' && ch != '1') throw new IllegalArgumentException("Invalid bit char: " + ch);
            b.set(i, ch == '1');
        }
        return b;
    }
}