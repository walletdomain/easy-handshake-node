package handshake.node.crypto;

/** Original (pre-NIST, 0x01 padding) Keccak-256, for the OP_KECCAK script opcode. */
public final class Keccak256 {
    private Keccak256() {}

    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    private static final int[] ROT = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
    private static final int[] PI = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

    private static void permute(long[] s) {
        long[] c = new long[5];
        for (int round = 0; round < 24; round++) {
            for (int i = 0; i < 5; i++) c[i] = s[i] ^ s[i+5] ^ s[i+10] ^ s[i+15] ^ s[i+20];
            for (int i = 0; i < 5; i++) {
                long d = c[(i + 4) % 5] ^ Long.rotateLeft(c[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) s[j + i] ^= d;
            }
            long t = s[1];
            for (int i = 0; i < 24; i++) {
                int j = PI[i];
                long tmp = s[j];
                s[j] = Long.rotateLeft(t, ROT[i]);
                t = tmp;
            }
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) c[i] = s[j + i];
                for (int i = 0; i < 5; i++) s[j + i] ^= (~c[(i + 1) % 5]) & c[(i + 2) % 5];
            }
            s[0] ^= RC[round];
        }
    }

    public static byte[] hash(byte[] msg) {
        final int rate = 136;
        long[] s = new long[25];
        int padLen = (msg.length / rate + 1) * rate;
        byte[] p = new byte[padLen];
        System.arraycopy(msg, 0, p, 0, msg.length);
        p[msg.length] ^= 0x01;
        p[padLen - 1] ^= (byte) 0x80;
        for (int off = 0; off < padLen; off += rate) {
            for (int i = 0; i < rate / 8; i++) {
                long v = 0;
                for (int k = 7; k >= 0; k--) v = (v << 8) | (p[off + i*8 + k] & 0xffL);
                s[i] ^= v;
            }
            permute(s);
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) out[i] = (byte) (s[i / 8] >>> (8 * (i % 8)));
        return out;
    }
}