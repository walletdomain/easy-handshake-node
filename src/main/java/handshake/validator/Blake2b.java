package handshake.validator;

import java.util.Arrays;

/**
 * Blake2b — pure Java implementation of the BLAKE2b hash function.
    * <p>
 * Used throughout Handshake for:
 *   - Transaction ID computation (Blake2b-256 of base tx)
 *   - Block hash computation (Blake2b-256 of header)
 *   - Address hash computation (Blake2b-160 of public key)
 *   - Brontide key derivation (HKDF with Blake2b-256)
    * <p>
 * Supports output lengths of 20, 32, and 64 bytes.
 * Supports keyed hashing (HMAC-like) for HKDF.
 */
public final class Blake2b {

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    private static final byte[] SIGMA = {
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
            14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
            11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
            7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
            9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
            2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
            12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
            13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
            6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
            10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0
    };

    // ── Public API ────────────────────────────────────────────────────────────

    /** Hashes data with no key, returning outLen bytes (20, 32, or 64). */
    public static byte[] hash(byte[] data, int outLen) {
        return hash(data, new byte[0], outLen);
    }

    /** Hashes data with a key, returning outLen bytes. */
    public static byte[] hash(byte[] data, byte[] key, int outLen) {
        Blake2bState state = new Blake2bState(outLen, key);
        state.update(data, 0, data.length);
        return state.digest();
    }

    /** Convenience: Blake2b-256. */
    public static byte[] hash256(byte[] data) {
        return hash(data, 32);
    }

    /** Convenience: Blake2b-160 (used for address hashing). */
    public static byte[] hash160(byte[] data) {
        return hash(data, 20);
    }

    /** Convenience: Blake2b-512. */
    public static byte[] hash512(byte[] data) {
        return hash(data, 64);
    }

    /**
     * HMAC-Blake2b using the keyed hash mode.
     * Used in Brontide's HKDF key derivation.
     */
    public static byte[] hmac(byte[] key, byte[] data, int outLen) {
        // Blake2b supports native keyed hashing — no need for HMAC construction
        byte[] k = key.length > 64 ? hash(key, 64) : key;
        return hash(data, k, outLen);
    }

    // ── State machine ─────────────────────────────────────────────────────────

    public static class Blake2bState {
        private final long[] h = new long[8];
        private final long[] t = new long[2];
        private final long[] f = new long[2];
        private final byte[] buf = new byte[128];
        private int bufLen;
        private final int outLen;

        public Blake2bState(int outLen, byte[] key) {
            this.outLen = outLen;
            // Initialize state
            System.arraycopy(IV, 0, h, 0, 8);
            int klen = key != null ? key.length : 0;
            h[0] ^= 0x01010000L ^ ((long) klen << 8) ^ outLen;
            bufLen = 0;
            Arrays.fill(buf, (byte) 0);
            if (klen > 0) {
                System.arraycopy(key, 0, buf, 0, klen);
                bufLen = 128;
            }
        }

        public void update(byte[] data, int off, int len) {
            if (len == 0) return;
            int left = bufLen;
            int fill = 128 - left;
            if (left > 0 && len > fill) {
                System.arraycopy(data, off, buf, left, fill);
                addCount(128);
                compress(buf, 0, false);
                bufLen = 0;
                off += fill;
                len -= fill;
            }
            while (len > 128) {
                addCount(128);
                compress(data, off, false);
                off += 128;
                len -= 128;
            }
            if (len > 0) {
                System.arraycopy(data, off, buf, bufLen, len);
                bufLen += len;
            }
        }

        public byte[] digest() {
            // Final block
            addCount(bufLen);
            f[0] = -1L;
            // Zero-pad remaining buffer
            Arrays.fill(buf, bufLen, 128, (byte) 0);
            compress(buf, 0, true);
            // Extract output
            byte[] out = new byte[outLen];
            for (int i = 0; i < outLen; i++) {
                out[i] = (byte) (h[i >>> 3] >>> ((i & 7) << 3));
            }
            return out;
        }

        private void addCount(long n) {
            t[0] += n;
            if (t[0] < n) t[1]++;
        }

        private void compress(byte[] block, int off, boolean last) {
            long[] m = new long[16];
            for (int i = 0; i < 16; i++) {
                int p = off + i * 8;
                m[i] = ((long)(block[p]     & 0xFF))
                        | ((long)(block[p + 1] & 0xFF) << 8)
                        | ((long)(block[p + 2] & 0xFF) << 16)
                        | ((long)(block[p + 3] & 0xFF) << 24)
                        | ((long)(block[p + 4] & 0xFF) << 32)
                        | ((long)(block[p + 5] & 0xFF) << 40)
                        | ((long)(block[p + 6] & 0xFF) << 48)
                        | ((long)(block[p + 7] & 0xFF) << 56);
            }
            long[] v = new long[16];
            System.arraycopy(h, 0, v, 0, 8);
            System.arraycopy(IV, 0, v, 8, 8);
            v[12] ^= t[0];
            v[13] ^= t[1];
            if (last) v[14] ^= -1L;

            // Blake2b requires exactly 12 rounds of compression, not 10.
            // This is a huge, foundational bug: it was apparently fixed
            // once, very early in this project's history, but the file
            // being worked with this entire recent session had silently
            // reverted to 10 rounds. With the wrong round count, Blake2b
            // still produces deterministic, internally self-consistent
            // output -- which is exactly why this was invisible in every
            // local round-trip/self-consistency test throughout this
            // whole project, and only surfaced now via direct comparison
            // against real, independently-verified ground truth (both
            // real hsd's own output and Python's standard hashlib).
            //
            // The SIGMA table only holds 10 rounds' worth of permutation
            // data -- that's correct per the real spec, since Blake2b's
            // message schedule genuinely has a period of 10: rounds 11
            // and 12 are defined to REUSE the schedules from rounds 1 and
            // 2, not need new entries. The round index into SIGMA must
            // wrap with % 10 while the outer mixing loop still runs the
            // full 12 rounds.
            for (int r = 0; r < 12; r++) {
                int s = (r % 10) * 16;
                v = G(v, 0, 4,  8, 12, m[SIGMA[s]],      m[SIGMA[s+1]]);
                v = G(v, 1, 5,  9, 13, m[SIGMA[s+2]],    m[SIGMA[s+3]]);
                v = G(v, 2, 6, 10, 14, m[SIGMA[s+4]],    m[SIGMA[s+5]]);
                v = G(v, 3, 7, 11, 15, m[SIGMA[s+6]],    m[SIGMA[s+7]]);
                v = G(v, 0, 5, 10, 15, m[SIGMA[s+8]],    m[SIGMA[s+9]]);
                v = G(v, 1, 6, 11, 12, m[SIGMA[s+10]],   m[SIGMA[s+11]]);
                v = G(v, 2, 7,  8, 13, m[SIGMA[s+12]],   m[SIGMA[s+13]]);
                v = G(v, 3, 4,  9, 14, m[SIGMA[s+14]],   m[SIGMA[s+15]]);
            }
            for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
        }

        private static long[] G(long[] v, int a, int b, int c, int d, long x, long y) {
            v[a] = v[a] + v[b] + x;
            v[d] = Long.rotateRight(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = Long.rotateRight(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y;
            v[d] = Long.rotateRight(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = Long.rotateRight(v[b] ^ v[c], 63);
            return v;
        }
    }

    // ── HKDF ─────────────────────────────────────────────────────────────────

    /**
     * HKDF-Extract using Blake2b-256.
     * Returns a 32-byte pseudorandom key.
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        if (salt == null || salt.length == 0) salt = new byte[32];
        return hmac(salt, ikm, 32);
    }

    /**
     * HKDF-Expand using Blake2b-256.
     * Returns outLen bytes of key material.
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int outLen) {
        byte[] result = new byte[outLen];
        byte[] t = new byte[0];
        int pos = 0, counter = 1;
        while (pos < outLen) {
            byte[] input = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, input, 0, t.length);
            System.arraycopy(info, 0, input, t.length, info.length);
            input[input.length - 1] = (byte) counter++;
            t = hmac(prk, input, 32);
            int copy = Math.min(outLen - pos, t.length);
            System.arraycopy(t, 0, result, pos, copy);
            pos += copy;
        }
        return result;
    }
}