package handshake.node;

import java.util.Arrays;

/**
 * Mempool-level transaction signature verification.
    * <p>
 * Ported directly from real hsd source (lib/primitives/tx.js's
 * signatureHash(), lib/script/script.js's fromPubkeyhash(), and
 * lib/script/common.js's opcode/hashType constants) rather than assumed
 * to match Bitcoin's sighash algorithm -- it doesn't. Two real
 * differences confirmed directly from source: the sighash preimage is
 * hashed with Blake2b throughout (not SHA256d), and address hashing
 * uses a Handshake-specific OP_BLAKE160 opcode (0xc0) rather than
 * Bitcoin's OP_HASH160 -- meaning the actual hash function is
 * Blake2b-160, not RIPEMD160(SHA256(x)).
    * <p>
 * Only handles the standard witness-pubkeyhash case (a 20-byte address
 * hash, matching a single [signature, pubkey] witness stack) -- this
 * covers the overwhelming majority of ordinary spends. Anything else
 * (script-hash outputs, non-standard witness shapes) is intentionally
 * left unverified rather than guessed at, since a wrong verification
 * would be worse than none -- it could reject genuinely valid
 * transactions or, worse, silently accept invalid ones through a
 * mis-implemented path.
 */
public class TxVerify {

    // Opcodes, confirmed against real lib/script/common.js
    private static final int OP_DUP         = 0x76;
    private static final int OP_BLAKE160    = 0xc0;
    private static final int OP_EQUALVERIFY = 0x88;
    private static final int OP_CHECKSIG    = 0xac;

    // Sighash types, confirmed against real lib/script/common.js
    public static final int SIGHASH_ALL           = 1;
    public static final int SIGHASH_NONE          = 2;
    public static final int SIGHASH_SINGLE        = 3;
    public static final int SIGHASH_SINGLEREVERSE = 4;
    public static final int SIGHASH_NOINPUT       = 0x40;
    public static final int SIGHASH_ANYONECANPAY  = 0x80;

    /**
     * Verifies input[inputIndex] of tx correctly spends a standard
     * witness-pubkeyhash output with the given hash and value. Returns
     * false (not an exception) for anything that isn't the standard,
     * verifiable case -- covenant/coinbase inputs, non-P2PKH hash
     * lengths, malformed witness stacks -- so callers can decide how to
     * treat "couldn't verify" versus "verified and failed" if that
     * distinction ever matters.
     */
    public static boolean verifyInput(TxParser.ParsedTx tx, int inputIndex,
                                      byte[] addrHash, long value) {
        if (addrHash == null || addrHash.length != 20) return false; // not P2PKH-shaped
        TxParser.Input input = tx.inputs.get(inputIndex);
        if (input.witness.size() != 2) return false; // expect exactly [sig, pubkey]

        byte[] sigWithType = input.witness.get(0);
        byte[] pubkey      = input.witness.get(1);
        if (sigWithType.length < 1 || pubkey.length != 33) return false;

        // Confirm the pubkey actually hashes to the address this input
        // claims to spend from -- without this check, ANY valid
        // signature from ANY key would pass, since the ECDSA check
        // alone only proves the signer owns SOME key, not that it's
        // the right one for this UTXO.
        byte[] computedHash = Blake2b.hash(pubkey, 20);
        if (!Arrays.equals(computedHash, addrHash)) return false;

        // Standard convention: signature has the 1-byte sighash type
        // appended after the DER-encoded signature itself.
        int sighashType = sigWithType[sigWithType.length - 1] & 0xFF;
        byte[] derSig = Arrays.copyOf(sigWithType, sigWithType.length - 1);

        byte[] prevScript = buildP2PKHScript(addrHash);
        byte[] sighash = computeSignatureHash(tx, inputIndex, prevScript, value, sighashType);

        return Secp256k1.verify(sighash, derSig, pubkey);
    }

    /**
     * Real hsd's Script.fromPubkeyhash(): OP_DUP OP_BLAKE160 <20-byte
     * push> OP_EQUALVERIFY OP_CHECKSIG -- exactly 25 bytes. This is the
     * "prev" script signatureHash() expects for a witness-pubkeyhash
     * input, NOT the raw (tiny) witness program itself.
     */
    private static byte[] buildP2PKHScript(byte[] hash20) {
        byte[] script = new byte[25];
        script[0] = (byte) OP_DUP;
        script[1] = (byte) OP_BLAKE160;
        script[2] = 0x14; // push 20 bytes
        System.arraycopy(hash20, 0, script, 3, 20);
        script[23] = (byte) OP_EQUALVERIFY;
        script[24] = (byte) OP_CHECKSIG;
        return script;
    }

    /**
     * Ported directly from real hsd's tx.js signatureHash(). Blake2b
     * throughout (not SHA256d). NOINPUT is not implemented (rare, not
     * needed for standard mempool verification).
     */
    static byte[] computeSignatureHash(TxParser.ParsedTx tx, int index,
                                       byte[] prevScript, long value, int type) {
        TxParser.Input input = tx.inputs.get(index);
        byte[] prevouts  = new byte[32];
        byte[] sequences = new byte[32];
        byte[] outputsHash = new byte[32];

        if ((type & SIGHASH_ANYONECANPAY) == 0) {
            byte[] buf = new byte[tx.inputs.size() * 36];
            int pos = 0;
            for (TxParser.Input in : tx.inputs) {
                System.arraycopy(in.prevHash, 0, buf, pos, 32); pos += 32;
                pos = writeLE32(buf, pos, in.prevIndex);
            }
            prevouts = Blake2b.hash256(buf);
        }

        int baseType = type & 0x1f;
        if ((type & SIGHASH_ANYONECANPAY) == 0
                && baseType != SIGHASH_SINGLE
                && baseType != SIGHASH_SINGLEREVERSE
                && baseType != SIGHASH_NONE) {
            byte[] buf = new byte[tx.inputs.size() * 4];
            int pos = 0;
            for (TxParser.Input in : tx.inputs) {
                pos = writeLE32(buf, pos, in.sequence);
            }
            sequences = Blake2b.hash256(buf);
        }

        if (baseType != SIGHASH_SINGLE && baseType != SIGHASH_SINGLEREVERSE && baseType != SIGHASH_NONE) {
            int size = 0;
            byte[][] encoded = new byte[tx.outputs.size()][];
            for (int i = 0; i < tx.outputs.size(); i++) {
                encoded[i] = encodeOutput(tx.outputs.get(i));
                size += encoded[i].length;
            }
            byte[] buf = new byte[size];
            int pos = 0;
            for (byte[] e : encoded) {
                System.arraycopy(e, 0, buf, pos, e.length);
                pos += e.length;
            }
            outputsHash = Blake2b.hash256(buf);
        } else if (baseType == SIGHASH_SINGLE) {
            if (index < tx.outputs.size()) {
                outputsHash = Blake2b.hash256(encodeOutput(tx.outputs.get(index)));
            }
        } else if (baseType == SIGHASH_SINGLEREVERSE) {
            int idx = tx.outputs.size() - 1 - index;
            if (idx >= 0) {
                outputsHash = Blake2b.hash256(encodeOutput(tx.outputs.get(idx)));
            }
        }

        byte[] preimage = new byte[4 + 32 + 32 + 32 + 4 + (1 + prevScript.length) + 8 + 4 + 32 + 4 + 4];
        int pos = 0;
        pos = writeLE32(preimage, pos, tx.version);
        System.arraycopy(prevouts, 0, preimage, pos, 32); pos += 32;
        System.arraycopy(sequences, 0, preimage, pos, 32); pos += 32;
        System.arraycopy(input.prevHash, 0, preimage, pos, 32); pos += 32;
        pos = writeLE32(preimage, pos, input.prevIndex);
        // varBytes: single-byte length prefix is sufficient (25-byte P2PKH script)
        preimage[pos++] = (byte) prevScript.length;
        System.arraycopy(prevScript, 0, preimage, pos, prevScript.length); pos += prevScript.length;
        pos = writeLE64(preimage, pos, value);
        pos = writeLE32(preimage, pos, input.sequence);
        System.arraycopy(outputsHash, 0, preimage, pos, 32); pos += 32;
        pos = writeLE32(preimage, pos, tx.locktime);
        writeLE32(preimage, pos, type);

        return Blake2b.hash256(preimage);
    }

    /** Re-serializes a parsed Output back to its raw wire bytes (value +
     *  addrVersion + addrHashLen + addrHash + covenant), needed to
     *  recompute the outputs hash for signing/verification -- and, more
     *  generally, to build ANY output's raw bytes, including a freshly
     *  constructed one for createrawtransaction (not just a re-encoding
     *  of an already-parsed one). */
    public static byte[] encodeOutput(TxParser.Output out) {
        int covSize = 1 + 1; // type + item count varint (assumes <0xFD items)
        for (TxParser.CovenantItem item : out.covenant.items) {
            covSize += 1 + item.data.length; // assumes <0xFD length
        }
        byte[] buf = new byte[8 + 1 + 1 + out.addrHash.length + covSize];
        int pos = 0;
        pos = writeLE64(buf, pos, out.value);
        buf[pos++] = (byte) out.addrVersion;
        buf[pos++] = (byte) out.addrHash.length;
        System.arraycopy(out.addrHash, 0, buf, pos, out.addrHash.length); pos += out.addrHash.length;
        buf[pos++] = (byte) out.covenant.type;
        buf[pos++] = (byte) out.covenant.items.size();
        for (TxParser.CovenantItem item : out.covenant.items) {
            buf[pos++] = (byte) item.data.length;
            System.arraycopy(item.data, 0, buf, pos, item.data.length);
            pos += item.data.length;
        }
        return buf;
    }

    private static int writeLE32(byte[] buf, int pos, int v) {
        buf[pos] = (byte) v; buf[pos+1] = (byte) (v >>> 8);
        buf[pos+2] = (byte) (v >>> 16); buf[pos+3] = (byte) (v >>> 24);
        return pos + 4;
    }

    private static int writeLE64(byte[] buf, int pos, long v) {
        for (int i = 0; i < 8; i++) buf[pos+i] = (byte) (v >>> (i * 8));
        return pos + 8;
    }

    /**
     * Builds a complete, unsigned raw transaction from freshly-constructed
     * inputs/outputs (e.g. for createrawtransaction) -- version + inputs
     * + outputs + locktime + one empty witness stack per input (matching
     * the standard convention of an unsigned tx still carrying the
     * witness section, just with zero items in it, so it round-trips
     * correctly through this project's own TxParser.parse()). Assumes
     * fewer than 0xFD inputs/outputs, which is realistic for anything
     * built through an RPC call like this one.
     */
    public static byte[] serializeUnsignedTx(int version, java.util.List<TxParser.Input> inputs,
                                             java.util.List<TxParser.Output> outputs, int locktime) {
        byte[][] encodedOutputs = new byte[outputs.size()][];
        int outputsSize = 0;
        for (int i = 0; i < outputs.size(); i++) {
            encodedOutputs[i] = encodeOutput(outputs.get(i));
            outputsSize += encodedOutputs[i].length;
        }

        int size = 4 + 1 + inputs.size() * 40 + 1 + outputsSize + 4 + inputs.size();
        byte[] buf = new byte[size];
        int pos = 0;
        pos = writeLE32(buf, pos, version);
        buf[pos++] = (byte) inputs.size();
        for (TxParser.Input in : inputs) {
            System.arraycopy(in.prevHash, 0, buf, pos, 32); pos += 32;
            pos = writeLE32(buf, pos, in.prevIndex);
            pos = writeLE32(buf, pos, in.sequence);
        }
        buf[pos++] = (byte) outputs.size();
        for (byte[] enc : encodedOutputs) {
            System.arraycopy(enc, 0, buf, pos, enc.length);
            pos += enc.length;
        }
        pos = writeLE32(buf, pos, locktime);
        for (int i = 0; i < inputs.size(); i++) {
            buf[pos++] = 0; // empty witness stack (0 items) -- this tx is unsigned
        }
        return buf;
    }
}