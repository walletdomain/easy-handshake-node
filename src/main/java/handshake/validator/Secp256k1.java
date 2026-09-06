package handshake.validator;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Secp256k1 — pure Java implementation of the secp256k1 elliptic curve.
    * <p>
 * Used for:
 *   - Deriving compressed public keys from private keys
 *   - ECDH shared secret computation (Brontide handshake)
 *   - Signature verification (transaction and block validation)
    * <p>
 * No external dependencies — everything is implemented using BigInteger.
 */
public final class Secp256k1 {

    private Secp256k1() {}

    // ── Curve parameters ──────────────────────────────────────────────────────

    private static final BigInteger P =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger N =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger Gx =
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger Gy =
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final BigInteger[] G = {Gx, Gy};

    // ── Point arithmetic ──────────────────────────────────────────────────────

    /** Point addition on secp256k1. Returns null for point at infinity. */
    private static BigInteger[] pointAdd(BigInteger[] p1, BigInteger[] p2) {
        if (p1 == null) return p2;
        if (p2 == null) return p1;
        BigInteger x1 = p1[0], y1 = p1[1];
        BigInteger x2 = p2[0], y2 = p2[1];

        if (x1.equals(x2) && !y1.equals(y2)) return null; // point at infinity

        BigInteger m;
        if (x1.equals(x2)) {
            // Point doubling
            m = x1.pow(2).multiply(BigInteger.valueOf(3))
                    .multiply(y1.multiply(BigInteger.TWO).modInverse(P))
                    .mod(P);
        } else {
            m = y2.subtract(y1)
                    .multiply(x2.subtract(x1).modInverse(P))
                    .mod(P);
        }

        BigInteger x3 = m.pow(2).subtract(x1).subtract(x2).mod(P);
        BigInteger y3 = m.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new BigInteger[]{x3, y3};
    }

    /** Scalar multiplication: k * point. */
    private static BigInteger[] scalarMult(BigInteger k, BigInteger[] point) {
        BigInteger[] result = null;
        BigInteger[] addend = point;
        k = k.mod(N);
        while (k.signum() > 0) {
            if (k.testBit(0)) result = pointAdd(result, addend);
            addend = pointAdd(addend, addend);
            k = k.shiftRight(1);
        }
        return result;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Derives the compressed 33-byte public key from a 32-byte private key.
     * Format: 0x02 or 0x03 prefix + 32-byte X coordinate.
     */
    public static byte[] compressedPublicKey(byte[] privateKey) {
        BigInteger k = new BigInteger(1, privateKey);
        BigInteger[] pub = scalarMult(k, G);
        if (pub == null) throw new IllegalArgumentException("Invalid private key");

        byte[] x = toBytes32(pub[0]);
        byte prefix = pub[1].testBit(0) ? (byte) 0x03 : (byte) 0x02;
        byte[] result = new byte[33];
        result[0] = prefix;
        System.arraycopy(x, 0, result, 1, 32);
        return result;
    }

    /**
     * Computes ECDH shared secret: privKey * pubKey → 32-byte X coordinate.
     * Used in Brontide handshake for key exchange.
        * <p>
     * @param compressedPubKey  33-byte compressed public key
     * @param privateKey        32-byte private key
     * @return                  32-byte shared secret (X coordinate)
     */
    /**
     * Computes ECDH shared secret: SHA-256(compressed 33-byte shared point).
     * Used in Brontide handshake for key exchange.
        * <p>
     * Real hsd's ecdh() hashes the 33-byte COMPRESSED shared point (prefix
     * byte + X-coordinate) -- NOT the raw 32-byte X-coordinate alone. This
     * was verified directly against real bcrypto ground truth: for
     * localPriv=0x1111...11, remotePriv=0x2222...22, ephemeralPriv=0x3333...33,
     * the shared X is 9110f876...ec71, and SHA-256 of that raw X gives
     * 910dd636... (WRONG), while SHA-256 of the compressed point
     * 029110f876...ec71 gives dad01099...98ac6 (the real, confirmed value).
        * <p>
     * @param compressedPubKey  33-byte compressed public key
     * @param privateKey        32-byte private key
     * @return                  32-byte SHA-256(compressed shared point)
     */
    public static byte[] ecdh(byte[] compressedPubKey, byte[] privateKey) {
        BigInteger[] pub = decompressPoint(compressedPubKey);
        BigInteger k = new BigInteger(1, privateKey);
        BigInteger[] shared = scalarMult(k, pub);
        if (shared == null) throw new IllegalArgumentException("ECDH produced point at infinity");
        byte[] x = toBytes32(shared[0]);
        byte prefix = shared[1].testBit(0) ? (byte) 0x03 : (byte) 0x02;
        byte[] compressed = new byte[33];
        compressed[0] = prefix;
        System.arraycopy(x, 0, compressed, 1, 32);
        try {
            return MessageDigest.getInstance("SHA-256").digest(compressed);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decompresses a 33-byte compressed public key to (x, y) point.
     */
    public static BigInteger[] decompressPoint(byte[] compressed) {
        if (compressed.length != 33)
            throw new IllegalArgumentException("Expected 33-byte compressed key");
        boolean odd = (compressed[0] == 0x03);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, 33));
        // y² = x³ + 7 (mod P)
        BigInteger y2 = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = y2.modPow(P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);
        if (y.testBit(0) != odd) y = P.subtract(y);
        return new BigInteger[]{x, y};
    }

    /**
     * Verifies a DER-encoded ECDSA signature against a message hash and
     * compressed public key.
        * <p>
     * @param msgHash    32-byte message hash (SHA256d or Blake2b)
     * @param derSig     DER-encoded signature (variable length)
     * @param pubKey     33-byte compressed public key
     * @return           true if signature is valid
     */
    public static boolean verify(byte[] msgHash, byte[] derSig, byte[] pubKey) {
        try {
            // Parse DER signature
            BigInteger[] rs = parseDerSignature(derSig);
            BigInteger r = rs[0], s = rs[1];

            // Validate r, s in [1, N-1]
            if (r.signum() <= 0 || r.compareTo(N) >= 0) return false;
            if (s.signum() <= 0 || s.compareTo(N) >= 0) return false;

            BigInteger z = new BigInteger(1, msgHash);
            BigInteger sInv = s.modInverse(N);
            BigInteger u1 = z.multiply(sInv).mod(N);
            BigInteger u2 = r.multiply(sInv).mod(N);

            BigInteger[] Q = decompressPoint(pubKey);
            BigInteger[] p1 = scalarMult(u1, G);
            BigInteger[] p2 = scalarMult(u2, Q);
            BigInteger[] point = pointAdd(p1, p2);

            if (point == null) return false;
            return point[0].mod(N).equals(r);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Parses a DER-encoded ECDSA signature into (r, s).
     */
    public static BigInteger[] parseDerSignature(byte[] der) {
        if (der[0] != 0x30) throw new IllegalArgumentException("Not a DER sequence");
        int offset = 2;
        if (der[offset] != 0x02) throw new IllegalArgumentException("Expected integer tag for r");
        int rLen = der[offset + 1] & 0xFF;
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(der, offset + 2, offset + 2 + rLen));
        offset += 2 + rLen;
        if (der[offset] != 0x02) throw new IllegalArgumentException("Expected integer tag for s");
        int sLen = der[offset + 1] & 0xFF;
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(der, offset + 2, offset + 2 + sLen));
        return new BigInteger[]{r, s};
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Converts BigInteger to exactly 32 bytes, zero-padded. */
    private static byte[] toBytes32(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        byte[] out = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    /** Returns compressed public key point as BigInteger array [x, y]. */
    public static BigInteger[] pubKeyPoint(byte[] privateKey) {
        return scalarMult(new BigInteger(1, privateKey), G);
    }

    /**
     * Signs a 32-byte message hash, returning a raw 64-byte (r || s)
     * signature -- NOT DER-encoded. Confirmed against a real example
     * from the official hsd docs (a signmessagewithprivkey output)
     * decoding to exactly 64 bytes, with no embedded recovery id --
     * hsd's own verifyMessage() brute-forces the recovery id (0-3) at
     * verification time instead of trusting one embedded in the
     * signature, so signing doesn't need to compute or embed one either.
        * <p>
     * Uses a fresh, securely-random per-signature nonce k, not RFC6979
     * deterministic nonce derivation (which real bcrypto likely uses) --
     * this doesn't affect correctness, since ECDSA's validity doesn't
     * depend on how k was chosen, only that it's genuinely secret and
     * uniformly random in [1, N-1]. It does mean this won't byte-for-byte
     * reproduce what bcrypto would produce for the same input, but that
     * was never a goal -- any valid signature verifies correctly.
        * <p>
     * Enforces low-S normalization (s <= N/2), matching the standard
     * malleability-prevention convention this project's own transaction
     * signature validation (TxVerify/common.js's isLowS check) already
     * requires elsewhere.
     */
    public static byte[] sign(byte[] msgHash, byte[] privateKey) {
        BigInteger z = new BigInteger(1, msgHash);
        BigInteger d = new BigInteger(1, privateKey);
        java.security.SecureRandom random = new java.security.SecureRandom();

        while (true) {
            byte[] kBytes = new byte[32];
            random.nextBytes(kBytes);
            BigInteger k = new BigInteger(1, kBytes).mod(N);
            if (k.signum() == 0) continue;

            BigInteger[] R = scalarMult(k, G);
            if (R == null) continue;
            BigInteger r = R[0].mod(N);
            if (r.signum() == 0) continue;

            BigInteger kInv = k.modInverse(N);
            BigInteger s = kInv.multiply(z.add(r.multiply(d))).mod(N);
            if (s.signum() == 0) continue;

            // Low-S normalization
            if (s.compareTo(N.shiftRight(1)) > 0) {
                s = N.subtract(s);
            }

            byte[] result = new byte[64];
            System.arraycopy(toBytes32(r), 0, result, 0, 32);
            System.arraycopy(toBytes32(s), 0, result, 32, 32);
            return result;
        }
    }

    /**
     * Recovers the compressed public key from a raw 64-byte (r || s)
     * signature, a 32-byte message hash, and a recovery id (0-3) --
     * standard ECDSA public key recovery, the same construction used by
     * e.g. Ethereum's ecrecover. Returns null if this recoveryId doesn't
     * correspond to a valid point for this r (the caller -- real hsd's
     * verifyMessage among them -- is expected to try all 4 values and
     * check which recovered key, if any, matches the expected address).
        * <p>
     * recoveryId bit 0 selects R's y-coordinate parity (0=even, 1=odd);
     * bit 1 would indicate r needed a +N adjustment (an extremely rare
     * case in practice, handled here for completeness even though it
     * essentially never triggers).
     */
    public static byte[] recover(byte[] msgHash, byte[] sig64, int recoveryId) {
        if (sig64.length != 64) return null;
        try {
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
            if (r.signum() <= 0 || s.signum() <= 0) return null;

            BigInteger x = r;
            if ((recoveryId & 2) != 0) x = x.add(N);
            if (x.compareTo(P) >= 0) return null;

            BigInteger y2 = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
            BigInteger y = y2.modPow(P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);
            // Verify this is actually a square root (x may not correspond
            // to a valid curve point at all for this r).
            if (!y.multiply(y).mod(P).equals(y2)) return null;
            boolean wantOdd = (recoveryId & 1) != 0;
            if (y.testBit(0) != wantOdd) y = P.subtract(y);
            BigInteger[] R = {x, y};

            BigInteger z = new BigInteger(1, msgHash);
            BigInteger rInv = r.modInverse(N);

            BigInteger[] sR = scalarMult(s, R);
            BigInteger[] zG = scalarMult(z.mod(N), G);
            BigInteger[] negZG = zG == null ? null : new BigInteger[]{zG[0], P.subtract(zG[1]).mod(P)};
            BigInteger[] Q = scalarMult(rInv, pointAdd(sR, negZG));
            if (Q == null) return null;

            byte[] result = new byte[33];
            result[0] = Q[1].testBit(0) ? (byte) 0x03 : (byte) 0x02;
            System.arraycopy(toBytes32(Q[0]), 0, result, 1, 32);
            return result;
        } catch (Exception e) {
            return null;
        }
    }
}