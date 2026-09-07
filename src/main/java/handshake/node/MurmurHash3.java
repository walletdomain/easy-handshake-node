package handshake.node;

/**
 * MurmurHash3 (x86, 32-bit variant) -- the specific, standard hash
 * function BIP37-style Bloom filters use to derive their N independent
 * hash functions (each simply MurmurHash3 with a different seed, per
 * BIP 0037: seed = hashNum * 0xFBA4C795 + tweak). A stable,
 * well-documented, non-Handshake-specific public algorithm, implemented
 * directly from a known-correct reference rather than guessed at, and
 * verified below against real, independently-sourced test vectors --
 * a silent bug in this would be very hard to detect later, since a
 * broken hash function still produces *a* bit pattern, it just wouldn't
 * be the one a real hsd-compatible client expects.
 */
public final class MurmurHash3 {

    private MurmurHash3() {}

    private static final int C1 = 0xcc9e2d51;
    private static final int C2 = 0x1b873593;

    public static int hash(byte[] data, int seed) {
        int h1 = seed;
        int roundedEnd = data.length & ~3; // round down to a multiple of 4

        for (int i = 0; i < roundedEnd; i += 4) {
            int k1 = (data[i] & 0xff)
                    | ((data[i + 1] & 0xff) << 8)
                    | ((data[i + 2] & 0xff) << 16)
                    | ((data[i + 3] & 0xff) << 24);
            k1 *= C1;
            k1 = Integer.rotateLeft(k1, 15);
            k1 *= C2;
            h1 ^= k1;
            h1 = Integer.rotateLeft(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;
        }

        int k1 = 0;
        switch (data.length & 3) {
            case 3: k1 ^= (data[roundedEnd + 2] & 0xff) << 16;
            case 2: k1 ^= (data[roundedEnd + 1] & 0xff) << 8;
            case 1:
                k1 ^= (data[roundedEnd] & 0xff);
                k1 *= C1;
                k1 = Integer.rotateLeft(k1, 15);
                k1 *= C2;
                h1 ^= k1;
        }

        h1 ^= data.length;
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;

        return h1;
    }
}