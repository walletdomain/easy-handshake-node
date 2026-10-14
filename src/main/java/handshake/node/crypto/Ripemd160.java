package handshake.node.crypto;

/** RIPEMD-160 (needed for OP_RIPEMD160 / OP_HASH160 script opcodes; not in the JDK). */
public final class Ripemd160 {
    private Ripemd160() {}

    private static final int[] RL = {
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
            3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
            1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
            4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
    private static final int[] RR = {
            5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
            6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
            15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
            8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
            12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
    private static final int[] SL = {
            11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
            7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
            11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
            11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
            9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
    private static final int[] SR = {
            8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
            9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
            9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
            15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
            8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
    private static final int[] KL = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
    private static final int[] KR = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};

    private static int f(int j, int x, int y, int z) {
        switch (j / 16) {
            case 0: return x ^ y ^ z;
            case 1: return (x & y) | (~x & z);
            case 2: return (x | ~y) ^ z;
            case 3: return (x & z) | (y & ~z);
            default: return x ^ (y | ~z);
        }
    }

    public static byte[] hash(byte[] msg) {
        int[] h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        int padLen = ((msg.length + 8) / 64 + 1) * 64;
        byte[] p = new byte[padLen];
        System.arraycopy(msg, 0, p, 0, msg.length);
        p[msg.length] = (byte) 0x80;
        long bits = (long) msg.length * 8;
        for (int i = 0; i < 8; i++) p[padLen - 8 + i] = (byte) (bits >>> (8 * i));
        int[] x = new int[16];
        for (int off = 0; off < padLen; off += 64) {
            for (int i = 0; i < 16; i++) {
                x[i] = (p[off + i*4] & 0xff) | ((p[off + i*4 + 1] & 0xff) << 8)
                        | ((p[off + i*4 + 2] & 0xff) << 16) | ((p[off + i*4 + 3] & 0xff) << 24);
            }
            int al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
            int ar = al, br = bl, cr = cl, dr = dl, er = el;
            for (int j = 0; j < 80; j++) {
                int t = Integer.rotateLeft(al + f(j, bl, cl, dl) + x[RL[j]] + KL[j / 16], SL[j]) + el;
                al = el; el = dl; dl = Integer.rotateLeft(cl, 10); cl = bl; bl = t;
                t = Integer.rotateLeft(ar + f(79 - j, br, cr, dr) + x[RR[j]] + KR[j / 16], SR[j]) + er;
                ar = er; er = dr; dr = Integer.rotateLeft(cr, 10); cr = br; br = t;
            }
            int t = h[1] + cl + dr;
            h[1] = h[2] + dl + er; h[2] = h[3] + el + ar; h[3] = h[4] + al + br; h[4] = h[0] + bl + cr; h[0] = t;
        }
        byte[] out = new byte[20];
        for (int i = 0; i < 5; i++) for (int k = 0; k < 4; k++) out[i*4 + k] = (byte) (h[i] >>> (8 * k));
        return out;
    }
}