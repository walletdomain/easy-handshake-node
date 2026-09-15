package handshake.node;

/**
 * Encodes and decodes the binary DNS-record format Handshake stores in
 * a name's UPDATE covenant data, matching real hsd's own
 * Resource.getJSON()/Resource.encode() shape exactly.
 * <p>
 * Decoding was ported directly from real hsd source: lib/dns/resource.js
 * (the record container and each record type's own read()/getJSON()),
 * lib/dns/common.js (hsTypes numeric constants), and node_modules/bns/
 * lib/encoding.js (the underlying DNS-name/string/IP wire encodings).
 * <p>
 * FIX: encoding added -- deliberately NOT attempting real hsd's own
 * name-COMPRESSION scheme (writing repeated names as backward pointers
 * into earlier parts of the same buffer). Compression is a pure
 * encoder-side space optimization, not something a decoder requires:
 * this project's own decodeToJson() already handles both compressed and
 * uncompressed names correctly (see readName()'s own pointer-following
 * logic), so writing every name out in full, every time, produces
 * strictly valid, standard-compliant wire data -- just not
 * maximally compact. A real, deliberate simplification, not an
 * oversight, and one with no correctness cost.
 *
 * Given how the equivalent situation played out elsewhere in this
 * project (Secp256k1.sign() existed, looked usable, and silently
 * produced the wrong wire format the first time anything actually tried
 * to use it for something new), every encoder method here is verified
 * with a real round trip back through this class's own, already-correct
 * decodeToJson() -- confirming what gets encoded is what actually comes
 * back out, not just that encoding runs without throwing.
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

    // Real, confirmed consensus limit (see rules.js's hasSaneCovenants(),
    // already verified elsewhere in this project): REGISTER and UPDATE
    // covenant items both cap resource data at 512 bytes. Enforced here
    // too, before ever handing encoded bytes to a transaction builder,
    // rather than letting an oversized UPDATE fail validation later with
    // a less specific error.
    public static final int MAX_RESOURCE_BYTES = 512;

    // ── Typed record representations for encoding ──────────────────────────

    public static abstract class Record { abstract int type(); }

    public static class NsRecord extends Record {
        public final String ns;
        public NsRecord(String ns) { this.ns = ns; }
        int type() { return TYPE_NS; }
    }

    public static class Glue4Record extends Record {
        public final String ns, address;
        public Glue4Record(String ns, String address) { this.ns = ns; this.address = address; }
        int type() { return TYPE_GLUE4; }
    }

    public static class Glue6Record extends Record {
        public final String ns, address;
        public Glue6Record(String ns, String address) { this.ns = ns; this.address = address; }
        int type() { return TYPE_GLUE6; }
    }

    public static class Synth4Record extends Record {
        public final String address;
        public Synth4Record(String address) { this.address = address; }
        int type() { return TYPE_SYNTH4; }
    }

    public static class Synth6Record extends Record {
        public final String address;
        public Synth6Record(String address) { this.address = address; }
        int type() { return TYPE_SYNTH6; }
    }

    public static class TxtRecord extends Record {
        public final java.util.List<String> txt;
        public TxtRecord(java.util.List<String> txt) { this.txt = txt; }
        int type() { return TYPE_TXT; }
    }

    public static class DsRecord extends Record {
        public final int keyTag, algorithm, digestType;
        public final byte[] digest;
        public DsRecord(int keyTag, int algorithm, int digestType, byte[] digest) {
            this.keyTag = keyTag; this.algorithm = algorithm; this.digestType = digestType; this.digest = digest;
        }
        int type() { return TYPE_DS; }
    }

    /** Encodes a full resource blob (version byte + each record in
     *  order) from a list of typed records -- the direct counterpart to
     *  decodeToJson(). Throws IllegalArgumentException if the result
     *  would exceed the real, consensus-enforced 512-byte limit, rather
     *  than silently returning oversized data a transaction builder
     *  would only find out was invalid later. */
    public static byte[] encode(java.util.List<Record> records) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(0); // version
        for (Record r : records) {
            out.write(r.type());
            encodeRecord(r, out);
        }
        byte[] result = out.toByteArray();
        if (result.length > MAX_RESOURCE_BYTES) {
            throw new IllegalArgumentException("Encoded resource data is " + result.length
                    + " bytes, exceeding the real, consensus-enforced limit of " + MAX_RESOURCE_BYTES);
        }
        return result;
    }

    private static void encodeRecord(Record r, java.io.ByteArrayOutputStream out) {
        if (r instanceof DsRecord ds) {
            writeU16BE(out, ds.keyTag);
            out.write(ds.algorithm);
            out.write(ds.digestType);
            if (ds.digest.length > 255) throw new IllegalArgumentException("DS digest too long: " + ds.digest.length);
            out.write(ds.digest.length);
            out.writeBytes(ds.digest);
        } else if (r instanceof NsRecord ns) {
            encodeName(ns.ns, out);
        } else if (r instanceof Glue4Record g4) {
            encodeName(g4.ns, out);
            encodeIPv4(g4.address, out);
        } else if (r instanceof Glue6Record g6) {
            encodeName(g6.ns, out);
            encodeIPv6(g6.address, out);
        } else if (r instanceof Synth4Record s4) {
            encodeIPv4(s4.address, out);
        } else if (r instanceof Synth6Record s6) {
            encodeIPv6(s6.address, out);
        } else if (r instanceof TxtRecord txt) {
            if (txt.txt.size() > 255) throw new IllegalArgumentException("Too many TXT strings: " + txt.txt.size());
            out.write(txt.txt.size());
            for (String s : txt.txt) {
                byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                if (b.length > 255) throw new IllegalArgumentException("TXT string too long (" + b.length + " bytes): " + s);
                out.write(b.length);
                out.writeBytes(b);
            }
        } else {
            throw new IllegalArgumentException("Unknown record type: " + r.getClass());
        }
    }

    /** Encodes a domain name in standard, UNCOMPRESSED DNS wire format:
     *  length-prefixed labels terminated by a zero byte. Deliberately
     *  does not attempt to parse the backslash-escape sequences
     *  readName() produces when DECODING (\\. for a literal dot inside a
     *  label, \\NNN for other special bytes) -- supports ordinary
     *  ASCII domain names, the overwhelming majority of real-world DNS
     *  records, and is explicit about that scope rather than silently
     *  mishandling an escaped input. */
    private static void encodeName(String name, java.io.ByteArrayOutputStream out) {
        if (name.equals(".") || name.isEmpty()) {
            out.write(0);
            return;
        }
        String trimmed = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        for (String label : trimmed.split("\\.", -1)) {
            byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            if (labelBytes.length == 0) throw new IllegalArgumentException("Empty label in name: " + name);
            if (labelBytes.length > 63) throw new IllegalArgumentException("Label too long (" + labelBytes.length + " bytes, max 63): " + label);
            out.write(labelBytes.length);
            out.writeBytes(labelBytes);
        }
        out.write(0);
    }

    private static void encodeIPv4(String address, java.io.ByteArrayOutputStream out) {
        String[] parts = address.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Not a valid IPv4 address: " + address);
        for (String p : parts) {
            int v = Integer.parseInt(p);
            if (v < 0 || v > 255) throw new IllegalArgumentException("Not a valid IPv4 address: " + address);
            out.write(v);
        }
    }

    private static void encodeIPv6(String address, java.io.ByteArrayOutputStream out) {
        try {
            byte[] bytes = java.net.InetAddress.getByName(address).getAddress();
            if (bytes.length != 16) throw new IllegalArgumentException("Not a valid IPv6 address: " + address);
            out.writeBytes(bytes);
        } catch (java.net.UnknownHostException e) {
            throw new IllegalArgumentException("Not a valid IPv6 address: " + address, e);
        }
    }

    private static void writeU16BE(java.io.ByteArrayOutputStream out, int v) {
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
    }

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