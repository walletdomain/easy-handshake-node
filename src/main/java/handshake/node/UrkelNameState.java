package handshake.node;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * A name's tree value, translated directly from real hsd's namestate.js
 * (read in full, including the truncated middle section) -- this is
 * exactly what gets txn.insert()-ed into the Urkel tree for each name,
 * confirmed directly from chaindb.js's _saveNames: "await
 * this.txn.insert(nameHash, ns.encode())".
 *
 * Deliberately does NOT replicate namestate.js's state()/toStats()/
 * getJSON() display logic -- this project already tracks a name's
 * display state independently (ChainDB.NameEntry), and those methods
 * don't affect the tree's computed root at all. Only the fields that
 * actually get serialized (and therefore affect the root) are here.
 */
public class UrkelNameState {

    public byte[] name = new byte[0];
    public byte[] data = new byte[0];       // the raw DNS resource blob
    public int height = 0;
    public int renewal = 0;

    /** null means "no owner" (matches real hsd's Outpoint.isNull()). */
    public byte[] ownerHash = null;         // 32 bytes when present
    public long ownerIndex = 0;

    public long value = 0;
    public long highest = 0;
    public int transfer = 0;
    public int revoked = 0;
    public int claimed = 0;
    public long renewals = 0;
    public boolean registered = false;
    public boolean expired = false;
    public boolean weak = false;

    /** Matches NameState.isNull() exactly -- true only when every
     *  field is at its default/zero value. A NameState reset to this
     *  state gets removed from the tree entirely (txn.remove()) rather
     *  than inserted, per chaindb.js's _saveNames. */
    public boolean isNull() {
        return height == 0
                && renewal == 0
                && ownerHash == null
                && value == 0
                && highest == 0
                && data.length == 0
                && transfer == 0
                && revoked == 0
                && claimed == 0
                && renewals == 0
                && !registered
                && !expired
                && !weak;
    }

    private int getField() {
        int field = 0;
        if (ownerHash != null) field |= 1;
        if (value != 0) field |= 1 << 1;
        if (highest != 0) field |= 1 << 2;
        if (transfer != 0) field |= 1 << 3;
        if (revoked != 0) field |= 1 << 4;
        if (claimed != 0) field |= 1 << 5;
        if (renewals != 0) field |= 1 << 6;
        if (registered) field |= 1 << 7;
        if (expired) field |= 1 << 8;
        if (weak) field |= 1 << 9;
        return field;
    }

    /** Matches NameState.write() exactly, field for field, in the same
     *  order, using the same bufio-style varints already proven
     *  correct elsewhere in this project (TxParser's readVarint). */
    public byte[] encode() {
        if (ownerHash != null && ownerHash.length != 32) {
            throw new IllegalStateException(
                    "ownerHash must be exactly 32 bytes when present, got " + ownerHash.length
                            + " -- decode() assumes a fixed 32-byte read, so a wrong length here would "
                            + "silently corrupt every field after it rather than fail loudly");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU8(out, name.length);
        writeBytes(out, name);
        writeU16(out, data.length);
        writeBytes(out, data);
        writeU32(out, height);
        writeU32(out, renewal);

        int field = getField();
        writeU16(out, field);

        if ((field & 1) != 0) {
            writeBytes(out, ownerHash);
            writeVarint(out, ownerIndex);
        }        if ((field & (1 << 1)) != 0) writeVarint(out, value);
        if ((field & (1 << 2)) != 0) writeVarint(out, highest);
        if ((field & (1 << 3)) != 0) writeU32(out, transfer);
        if ((field & (1 << 4)) != 0) writeU32(out, revoked);
        if ((field & (1 << 5)) != 0) writeU32(out, claimed);
        if ((field & (1 << 6)) != 0) writeVarint(out, renewals);

        return out.toByteArray();
    }

    public static UrkelNameState decode(byte[] data) {
        UrkelNameState ns = new UrkelNameState();
        Reader r = new Reader(data);

        int nameLen = r.readU8();
        ns.name = r.readBytes(nameLen);
        int dataLen = r.readU16();
        ns.data = r.readBytes(dataLen);
        ns.height = r.readU32();
        ns.renewal = r.readU32();

        int field = r.readU16();

        if ((field & 1) != 0) {
            ns.ownerHash = r.readBytes(32);
            ns.ownerIndex = r.readVarint();
        }
        if ((field & (1 << 1)) != 0) ns.value = r.readVarint();
        if ((field & (1 << 2)) != 0) ns.highest = r.readVarint();
        if ((field & (1 << 3)) != 0) ns.transfer = r.readU32();
        if ((field & (1 << 4)) != 0) ns.revoked = r.readU32();
        if ((field & (1 << 5)) != 0) ns.claimed = r.readU32();
        if ((field & (1 << 6)) != 0) ns.renewals = r.readVarint();
        ns.registered = (field & (1 << 7)) != 0;
        ns.expired = (field & (1 << 8)) != 0;
        ns.weak = (field & (1 << 9)) != 0;

        return ns;
    }

    // ── Little-endian fixed-width + bufio-style varint writers ─────────────

    private static void writeU8(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
    }

    private static void writeU16(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
    }

    private static void writeU32(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 24) & 0xFF);
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] b) {
        out.write(b, 0, b.length);
    }

    /** Same Bitcoin-style compact-size scheme already proven correct in
     *  TxParser's readVarint: <0xFD literal, 0xFD+u16, 0xFE+u32,
     *  0xFF+u64 -- this is the write-side counterpart. */
    private static void writeVarint(ByteArrayOutputStream out, long v) {
        if (v < 0xFD) {
            out.write((int) v);
        } else if (v <= 0xFFFF) {
            out.write(0xFD);
            out.write((int) (v & 0xFF));
            out.write((int) ((v >>> 8) & 0xFF));
        } else if (v <= 0xFFFFFFFFL) {
            out.write(0xFE);
            for (int i = 0; i < 4; i++) out.write((int) ((v >>> (8 * i)) & 0xFF));
        } else {
            out.write(0xFF);
            for (int i = 0; i < 8; i++) out.write((int) ((v >>> (8 * i)) & 0xFF));
        }
    }

    private static class Reader {
        final byte[] data;
        int pos = 0;
        Reader(byte[] data) { this.data = data; }

        int readU8() { return data[pos++] & 0xFF; }

        int readU16() {
            int v = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
            pos += 2;
            return v;
        }

        int readU32() {
            int v = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8)
                    | ((data[pos + 2] & 0xFF) << 16) | ((data[pos + 3] & 0xFF) << 24);
            pos += 4;
            return v;
        }

        byte[] readBytes(int len) {
            byte[] b = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            return b;
        }

        long readVarint() {
            int first = readU8();
            if (first < 0xFD) return first;
            if (first == 0xFD) return readU16();
            if (first == 0xFE) return readU32() & 0xFFFFFFFFL;
            long v = 0;
            for (int i = 0; i < 8; i++) v |= ((long) (data[pos++] & 0xFF)) << (8 * i);
            return v;
        }
    }
}