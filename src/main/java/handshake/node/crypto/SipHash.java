package handshake.node.crypto;

/**
 * SipHash-2-4 (64-bit output, 128-bit key), as used by BIP152 compact blocks.
 * Byte-compatible with bcrypto's siphash (checked against it in the differential tests).
 */
public final class SipHash {
    private SipHash() {}

    /** @param key 16 bytes (k0 || k1, little-endian) */
    public static long hash24(byte[] key, byte[] data) {
        if (key == null || key.length != 16) throw new IllegalArgumentException("siphash key must be 16 bytes");
        long k0 = le64(key, 0), k1 = le64(key, 8);
        long v0 = 0x736f6d6570736575L ^ k0;
        long v1 = 0x646f72616e646f6dL ^ k1;
        long v2 = 0x6c7967656e657261L ^ k0;
        long v3 = 0x7465646279746573L ^ k1;

        int len = data.length, end = len & ~7;
        for (int i = 0; i < end; i += 8) {
            long m = le64(data, i);
            v3 ^= m;
            for (int r = 0; r < 2; r++) {
                v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
                v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
                v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
                v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);
            }
            v0 ^= m;
        }
        long b = ((long) len) << 56;
        for (int i = 0; i < (len & 7); i++) b |= (data[end + i] & 0xFFL) << (8 * i);
        v3 ^= b;
        for (int r = 0; r < 2; r++) {
            v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
            v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
            v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
            v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);
        }
        v0 ^= b;
        v2 ^= 0xff;
        for (int r = 0; r < 4; r++) {
            v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
            v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
            v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
            v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);
        }
        return v0 ^ v1 ^ v2 ^ v3;
    }

    private static long le64(byte[] b, int o) {
        long x = 0;
        for (int i = 7; i >= 0; i--) x = (x << 8) | (b[o + i] & 0xFFL);
        return x;
    }
}