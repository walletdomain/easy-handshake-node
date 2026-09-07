package handshake.node;

/**
 * Bech32 address encoding/decoding for Handshake addresses.
    * <p>
 * Ported directly from real hsd source (node_modules/bcrypto/lib/
 * encoding/js/bech32.js) rather than assumed to match Bitcoin's bech32
 * exactly -- though in this specific case, it turned out to genuinely be
 * standard BIP-173 bech32 (confirmed via the exact checksum generator
 * polynomial constants and the "chk ^= 1" final constant, which rules
 * out bech32m or a Handshake-specific variant). That's not something to
 * have assumed without checking, though, given how many other things
 * this session turned out to differ from Bitcoin's conventions (Blake2b
 * instead of SHA256d for sighash, OP_BLAKE160 instead of OP_HASH160).
    * <p>
 * Network HRPs confirmed from multiple independent sources (handshake.org's
 * own claim page, HIP-0002's example addresses, and hsd's own regtest
 * API example): mainnet="hs", testnet="ts", regtest="rs", simnet="ss".
 */
public class Bech32 {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private static int polymod(int c) {
        int b = c >>> 25;
        return ((c & 0x1ffffff) << 5)
                ^ (0x3b6a57b2 & -((b >> 0) & 1))
                ^ (0x26508e6d & -((b >> 1) & 1))
                ^ (0x1ea119fa & -((b >> 2) & 1))
                ^ (0x3d4233dd & -((b >> 3) & 1))
                ^ (0x2a1462b3 & -((b >> 4) & 1));
    }

    /** Encodes a (version, hash) pair as a bech32 address string. */
    public static String encode(String hrp, int version, byte[] hash) {
        if (version < 0 || version > 31) throw new IllegalArgumentException("Invalid bech32 version.");
        if (hash.length < 2 || hash.length > 40) throw new IllegalArgumentException("Invalid bech32 data length.");

        // Real hsd's encode(): out[0] = version (placed directly, NOT put
        // through the bit conversion -- it's already small enough to fit
        // in 5 bits), THEN hash alone (not hash+version together) is
        // converted from 8-bit bytes to 5-bit groups starting at out[1].
        int[] converted = convert8to5(hash, true);
        int[] data = new int[1 + converted.length];
        data[0] = version;
        System.arraycopy(converted, 0, data, 1, converted.length);
        return serialize(hrp, data);
    }

    /** Decodes a bech32 address string, returning [hrp, version, hash]. */
    public static Object[] decode(String addr) {
        Object[] hd = deserialize(addr);
        String hrp = (String) hd[0];
        int[] data = (int[]) hd[1];

        if (data.length == 0 || data.length > 65) throw new IllegalArgumentException("Invalid bech32 data length.");
        int version = data[0];
        if (version > 31) throw new IllegalArgumentException("Invalid bech32 version.");

        int[] hashGroups = new int[data.length - 1];
        System.arraycopy(data, 1, hashGroups, 0, hashGroups.length);
        int[] hashInts = convert5to8(hashGroups, false);
        byte[] hash = new byte[hashInts.length];
        for (int i = 0; i < hashInts.length; i++) hash[i] = (byte) hashInts[i];

        if (hash.length < 2 || hash.length > 40) throw new IllegalArgumentException("Invalid bech32 data length.");
        return new Object[]{hrp, version, hash};
    }

    /** True if the string decodes as a syntactically valid bech32 address. */
    public static boolean isValid(String addr) {
        try {
            decode(addr);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String serialize(String hrp, int[] data) {
        if (hrp.isEmpty() || hrp.length() > 83) throw new IllegalArgumentException("Invalid bech32 human-readable part.");
        if (hrp.length() + 1 + data.length + 6 > 90) throw new IllegalArgumentException("Invalid bech32 data length.");

        StringBuilder str = new StringBuilder();
        int chk = 1;

        for (int i = 0; i < hrp.length(); i++) {
            int ch = hrp.charAt(i);
            if (ch < 33 || ch > 126) throw new IllegalArgumentException("Invalid bech32 character.");
            if (ch >= 65 && ch <= 90) throw new IllegalArgumentException("Invalid bech32 character.");
            chk = polymod(chk) ^ (ch >> 5);
        }
        chk = polymod(chk);
        for (int i = 0; i < hrp.length(); i++) {
            int ch = hrp.charAt(i);
            chk = polymod(chk) ^ (ch & 0x1f);
            str.append(hrp.charAt(i));
        }
        str.append('1');

        for (int ch : data) {
            if ((ch >> 5) != 0) throw new IllegalArgumentException("Invalid bech32 value.");
            chk = polymod(chk) ^ ch;
            str.append(CHARSET.charAt(ch));
        }

        for (int i = 0; i < 6; i++) chk = polymod(chk);
        chk ^= 1;
        for (int i = 0; i < 6; i++) {
            str.append(CHARSET.charAt((chk >>> ((5 - i) * 5)) & 0x1f));
        }
        return str.toString();
    }

    private static Object[] deserialize(String s) {
        if (s.length() < 8 || s.length() > 90) throw new IllegalArgumentException("Invalid bech32 string length.");

        boolean lower = false, upper = false;
        int hlen = 0;
        for (int i = 0; i < s.length(); i++) {
            int ch = s.charAt(i);
            if (ch < 33 || ch > 126) throw new IllegalArgumentException("Invalid bech32 character.");
            if (ch >= 97 && ch <= 122) lower = true;
            else if (ch >= 65 && ch <= 90) upper = true;
            else if (ch == 49) hlen = i; // '1'
        }
        if (hlen == 0) throw new IllegalArgumentException("Invalid bech32 human-readable part.");
        int dlen = s.length() - (hlen + 1);
        if (dlen < 6) throw new IllegalArgumentException("Invalid bech32 data length.");
        if (lower && upper) throw new IllegalArgumentException("Invalid bech32 casing.");

        int chk = 1;
        StringBuilder hrp = new StringBuilder();
        for (int i = 0; i < hlen; i++) {
            int ch = s.charAt(i);
            if (ch >= 65 && ch <= 90) ch += 32;
            chk = polymod(chk) ^ (ch >> 5);
            hrp.append((char) ch);
        }
        chk = polymod(chk);
        for (int i = 0; i < hlen; i++) {
            chk = polymod(chk) ^ (s.charAt(i) & 0x1f);
        }

        int[] data = new int[dlen - 6];
        int j = 0;
        for (int i = hlen + 1; i < s.length(); i++) {
            int val = charsetIndex(s.charAt(i));
            if (val == -1) throw new IllegalArgumentException("Invalid bech32 character.");
            chk = polymod(chk) ^ val;
            if (i < s.length() - 6) data[j++] = val;
        }
        if (chk != 1) throw new IllegalArgumentException("Invalid bech32 checksum.");

        return new Object[]{hrp.toString(), data};
    }

    private static int charsetIndex(char c) {
        char lc = Character.toLowerCase(c);
        int idx = CHARSET.indexOf(lc);
        return idx; // -1 if not found, matching real TABLE's -1 sentinel
    }

    /** Converts 8-bit bytes to 5-bit groups (padded), matching real hsd's
     *  convert(dst, dstoff=0, dstbits=5, src, srcoff=0, srcbits=8, pad=true). */
    private static int[] convert8to5(byte[] src, boolean pad) {
        int[] srcInts = new int[src.length];
        for (int i = 0; i < src.length; i++) srcInts[i] = src[i] & 0xFF;
        return convertGeneric(srcInts, 8, 5, pad);
    }

    /** Converts 5-bit groups back to 8-bit bytes, matching real hsd's
     *  convert(dst, dstoff=0, dstbits=8, src, srcoff=0, srcbits=5, pad=false). */
    private static int[] convert5to8(int[] src, boolean pad) {
        return convertGeneric(src, 5, 8, pad);
    }

    /** Generic base conversion between bit widths over a WHOLE source
     *  array (no offsets needed -- this project never converts a partial
     *  slice, unlike real hsd's version/hash-in-one-buffer approach,
     *  which is why encode()/decode() above split the version byte out
     *  before calling this rather than mirroring that exactly). */
    private static int[] convertGeneric(int[] src, int srcBits, int dstBits, boolean pad) {
        int mask = (1 << dstBits) - 1;
        int acc = 0, bits = 0;
        int[] out = new int[((src.length * srcBits + (pad ? dstBits - 1 : 0)) / dstBits) + 1];
        int j = 0;

        for (int value : src) {
            acc = (acc << srcBits) | value;
            bits += srcBits;
            while (bits >= dstBits) {
                bits -= dstBits;
                out[j++] = (acc >>> bits) & mask;
            }
        }

        int left = dstBits - bits;
        if (pad) {
            if (bits != 0) out[j++] = (acc << left) & mask;
        } else {
            if (((acc << left) & mask) != 0 || bits >= srcBits) {
                throw new IllegalArgumentException("Invalid bits.");
            }
        }

        int[] result = new int[j];
        System.arraycopy(out, 0, result, 0, j);
        return result;
    }

    /** Network HRP by network name, confirmed against real hsd/handshake.org sources. */
    public static String hrpForNetwork(String network) {
        return switch (network) {
            case "mainnet" -> "hs";
            case "testnet" -> "ts";
            case "regtest" -> "rs";
            case "simnet"  -> "ss";
            default -> "hs";
        };
    }
}