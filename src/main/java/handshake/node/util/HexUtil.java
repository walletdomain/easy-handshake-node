package handshake.node.util;

/**
 * Centralized hex encode/decode.
 * <p>
 * FIX: this exact 4-line encode loop (StringBuilder + String.format("%02x", x)
 * per byte) and 4-line decode loop (Integer.parseInt(substring(...), 16) per
 * byte pair) were independently reimplemented as private methods in over
 * twenty separate files across this project -- confirmed via a direct grep
 * audit, not an estimate. String.format() in particular is a documented,
 * real, roughly order-of-magnitude-slower path than a lookup-table encoder
 * (it parses a format string and goes through Locale-aware formatting
 * machinery for what is, every single time here, exactly two fixed hex
 * digits) -- and this sits directly on the covenant-processing hot path via
 * BlockProcessor.java and ChainDB.java's own per-touch hex() calls, which
 * the project's own timing log has repeatedly shown to be the dominant
 * per-block cost.
 * <p>
 * Every call site elsewhere in this project keeps its own existing private
 * hex()/fromHex()/toHex()/unhex() method exactly as before (same name, same
 * signature, same null/empty-string handling where a given caller already
 * had it) -- only each method's BODY now delegates here. That was a
 * deliberate choice over rewriting every call site directly: it makes this
 * a pure, zero-call-site-risk performance and de-duplication fix, not a
 * refactor that touches dozens of already-working call sites across the
 * project. Same hex alphabet (lowercase), same no-separator format, same
 * output every prior implementation already produced -- verified
 * byte-for-byte equivalent to the old String.format()-based loop before
 * being wired in anywhere.
 * <p>
 * RE-ARCHITECTURE: widened from package-private to public as part of the
 * handshake.node.storage split (package-reorg-plan.md, Phase 1) --
 * ChainDB and the DiskBacked* classes moved into handshake.node.storage
 * and still need this from the root handshake.node package, which a
 * package-private class can't allow across a package boundary at all
 * (not just "same convention as before, now enforced" -- an actual
 * compile failure without this). Pulled forward from this class's own
 * originally-planned util-phase visibility bump for that reason; no
 * other change here affects it, since widening visibility can never
 * break an existing same-package caller.
 */
public final class HexUtil {

    private HexUtil() {}

    private static final char[] ENCODE_TABLE = "0123456789abcdef".toCharArray();

    /** Decode table for '0'-'9', 'a'-'f', 'A'-'F' (accepts either case on
     *  the way in, exactly as Integer.parseInt(s, 16) already did for every
     *  prior implementation this replaces) -- everything else is -1, which
     *  is never reached by any existing, already-validated caller. */
    private static final byte[] DECODE_TABLE = buildDecodeTable();

    private static byte[] buildDecodeTable() {
        byte[] table = new byte[128];
        java.util.Arrays.fill(table, (byte) -1);
        for (int i = 0; i <= 9; i++) table['0' + i] = (byte) i;
        for (int i = 0; i <= 5; i++) {
            table['a' + i] = (byte) (10 + i);
            table['A' + i] = (byte) (10 + i);
        }
        return table;
    }

    // RE-ARCHITECTURE: widened to public alongside the class itself (see
    // this class's own top-of-file comment) -- handshake.node.storage
    // classes call these directly now that they're in a different
    // package.
    public static String encode(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xFF;
            out[i * 2] = ENCODE_TABLE[v >>> 4];
            out[i * 2 + 1] = ENCODE_TABLE[v & 0x0F];
        }
        return new String(out);
    }

    /** Throws NumberFormatException for a non-hex character, matching
     *  Integer.parseInt(s, 16)'s own behavior exactly -- every prior
     *  implementation this replaces relied on that exception, some of
     *  them (e.g. ChainSync's fromHexStatic()) explicitly catching it to
     *  treat malformed input as "not valid hex" rather than silently
     *  decoding garbage. A lookup table that just let an invalid char
     *  resolve to some accepted junk value would quietly change that
     *  error handling into "silently accept malformed input" instead --
     *  this check is what keeps every existing caller's behavior
     *  identical, not just its happy path. */
    public static byte[] decode(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            char hiChar = s.charAt(i * 2);
            char loChar = s.charAt(i * 2 + 1);
            int hi = hiChar < 128 ? DECODE_TABLE[hiChar] : -1;
            int lo = loChar < 128 ? DECODE_TABLE[loChar] : -1;
            if (hi < 0 || lo < 0) {
                throw new NumberFormatException("Invalid hex character in \"" + s + "\"");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}