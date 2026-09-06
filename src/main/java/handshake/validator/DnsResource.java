package handshake.validator;

/**
 * Decodes the binary DNS-record format Handshake stores in a name's
 * UPDATE covenant data, into JSON matching real hsd's own
 * Resource.getJSON() shape exactly: {"records": [{"type": "NS", ...}, ...]}.
    * <p>
 * Ported directly from real hsd source: lib/dns/resource.js (the record
 * container and each record type's own read()/getJSON()), lib/dns/
 * common.js (hsTypes numeric constants), and node_modules/bns/lib/
 * encoding.js (the underlying DNS-name/string/IP wire encodings).
    * <p>
 * Only decoding is implemented (read + getJSON), not encoding -- this is
 * all getnameresource needs (a read-only query over already-confirmed
 * covenant data), and encoding would additionally need real hsd's own
 * name-compression-map-building logic, a meaningfully bigger, separate
 * piece of work this project has no other use for.
 */
public class DnsResource {

    // hsTypes, confirmed against real lib/dns/common.js
    private static final int TYPE_DS     = 0;
    private static final int TYPE_NS     = 1;
    private static final int TYPE_GLUE4  = 2;
    private static final int TYPE_GLUE6  = 3;
    private static final int TYPE_SYNTH4 = 4;
    private static final int TYPE_SYNTH6 = 5;
    private static final int TYPE_TXT    = 6;

    /** Decodes a Resource blob into a JSON string matching real hsd's
     *  {"records": [...]} shape exactly. Returns "{"records":[]}" for
     *  anything unparseable, rather than throwing -- a malformed or
     *  unexpected covenant data blob isn't this project's problem to
     *  crash over, it just means "no resource data available". */
    public static String decodeToJson(byte[] data) {
        StringBuilder sb = new StringBuilder("{\"records\":[");
        try {
            int[] pos = {0};
            int version = data[pos[0]++] & 0xFF;
            if (version != 0) return "{\"records\":[]}";

            boolean first = true;
            while (pos[0] < data.length) {
                int type = data[pos[0]++] & 0xFF;
                String json = decodeRecord(type, data, pos);
                if (json == null) break; // unknown record type -- real hsd also just stops here
                if (!first) sb.append(",");
                sb.append(json);
                first = false;
            }
        } catch (Exception e) {
            return "{\"records\":[]}";
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String decodeRecord(int type, byte[] data, int[] pos) {
        switch (type) {
            case TYPE_DS: {
                int keyTag = readU16BE(data, pos);
                int algorithm = data[pos[0]++] & 0xFF;
                int digestType = data[pos[0]++] & 0xFF;
                int digestLen = data[pos[0]++] & 0xFF;
                byte[] digest = readBytes(data, pos, digestLen);
                return "{\"type\":\"DS\",\"keyTag\":" + keyTag + ",\"algorithm\":" + algorithm
                        + ",\"digestType\":" + digestType + ",\"digest\":\"" + hex(digest) + "\"}";
            }
            case TYPE_NS: {
                String ns = readName(data, pos);
                return "{\"type\":\"NS\",\"ns\":\"" + jsonEscape(ns) + "\"}";
            }
            case TYPE_GLUE4: {
                String ns = readName(data, pos);
                String addr = readIPv4(data, pos);
                return "{\"type\":\"GLUE4\",\"ns\":\"" + jsonEscape(ns) + "\",\"address\":\"" + addr + "\"}";
            }
            case TYPE_GLUE6: {
                String ns = readName(data, pos);
                String addr = readIPv6(data, pos);
                return "{\"type\":\"GLUE6\",\"ns\":\"" + jsonEscape(ns) + "\",\"address\":\"" + addr + "\"}";
            }
            case TYPE_SYNTH4: {
                String addr = readIPv4(data, pos);
                return "{\"type\":\"SYNTH4\",\"address\":\"" + addr + "\"}";
            }
            case TYPE_SYNTH6: {
                String addr = readIPv6(data, pos);
                return "{\"type\":\"SYNTH6\",\"address\":\"" + addr + "\"}";
            }
            case TYPE_TXT: {
                int count = data[pos[0]++] & 0xFF;
                StringBuilder items = new StringBuilder("[");
                for (int i = 0; i < count; i++) {
                    if (i > 0) items.append(",");
                    int len = data[pos[0]++] & 0xFF;
                    byte[] raw = readBytes(data, pos, len);
                    items.append("\"").append(jsonEscape(new String(raw, java.nio.charset.StandardCharsets.UTF_8))).append("\"");
                }
                items.append("]");
                return "{\"type\":\"TXT\",\"txt\":" + items + "}";
            }
            default:
                return null; // unknown type -- real hsd's own read() loop also just breaks here
        }
    }

    /**
     * DNS name wire format: a sequence of length-prefixed labels
     * terminated by a zero byte, with optional compression pointers
     * (top two bits of the length byte set) that jump elsewhere in the
     * SAME buffer and continue reading from there -- confirmed directly
     * against real bns/lib/encoding.js's readName(). Real hsd's own
     * Resource.encode() always builds these with a real compression map,
     * so a decoder that can't follow pointers would fail on real,
     * legitimately-encoded covenant data, not just edge cases.
     */
    private static String readName(byte[] data, int[] posRef) {
        StringBuilder name = new StringBuilder();
        int off = posRef[0];
        int returnOffset = -1;
        int pointerHops = 0;

        while (true) {
            int c = data[off++] & 0xFF;
            if (c == 0x00) break;

            if ((c & 0xc0) == 0x00) {
                int len = c;
                for (int j = 0; j < len; j++) {
                    int b = data[off + j] & 0xFF;
                    char ch = (char) b;
                    if (ch == '.' || ch == '(' || ch == ')' || ch == ';'
                            || ch == ' ' || ch == '@' || ch == '"' || ch == '\\') {
                        name.append('\\').append(ch);
                    } else if (b < 0x20 || b > 0x7e) {
                        name.append('\\').append(String.format("%03d", b));
                    } else {
                        name.append(ch);
                    }
                }
                name.append('.');
                off += len;
            } else if ((c & 0xc0) == 0xc0) {
                int c1 = data[off++] & 0xFF;
                if (returnOffset < 0) returnOffset = off;
                pointerHops++;
                if (pointerHops > 10) throw new RuntimeException("Too many compression pointers");
                off = ((c ^ 0xc0) << 8) | c1;
            } else {
                throw new RuntimeException("Invalid name label byte");
            }
        }

        posRef[0] = returnOffset >= 0 ? returnOffset : off;
        return name.length() == 0 ? "." : name.toString();
    }

    private static String readIPv4(byte[] data, int[] pos) {
        int a = data[pos[0]++] & 0xFF, b = data[pos[0]++] & 0xFF,
                c = data[pos[0]++] & 0xFF, d = data[pos[0]++] & 0xFF;
        return a + "." + b + "." + c + "." + d;
    }

    private static String readIPv6(byte[] data, int[] pos) {
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((data[pos[0]] & 0xFF) << 8) | (data[pos[0] + 1] & 0xFF);
            pos[0] += 2;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i > 0) sb.append(":");
            sb.append(Integer.toHexString(groups[i]));
        }
        return sb.toString();
    }

    private static int readU16BE(byte[] data, int[] pos) {
        int v = ((data[pos[0]] & 0xFF) << 8) | (data[pos[0] + 1] & 0xFF);
        pos[0] += 2;
        return v;
    }

    private static byte[] readBytes(byte[] data, int[] pos, int len) {
        byte[] b = java.util.Arrays.copyOfRange(data, pos[0], pos[0] + len);
        pos[0] += len;
        return b;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }
}