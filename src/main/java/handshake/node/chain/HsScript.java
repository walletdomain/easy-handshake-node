package handshake.node.chain;

import handshake.node.crypto.Blake2b;
import handshake.node.crypto.Keccak256;
import handshake.node.crypto.Ripemd160;
import handshake.node.crypto.Secp256k1;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Handshake script interpreter, ported opcode-for-opcode from hsd
 * (lib/script/script.js execute() and verify(), stack.js, scriptnum.js,
 * opcode.js, common.js). Handshake has no scriptSig: every spend is a
 * witness. Version-0 addresses are either a 20-byte pubkey hash (the witness
 * must be [signature, pubkey]) or a 32-byte SHA3-256 script hash (the last
 * witness item is the script, the rest are its arguments). Version 31 is
 * unspendable; any other version is anyone-can-spend ("upgradable") unless
 * the DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM policy flag is set.
 */
public final class HsScript {
    private HsScript() {}

    // ── Limits (consensus.js) ────────────────────────────────────────────────
    public static final int MAX_SCRIPT_SIZE = 10000;
    public static final int MAX_SCRIPT_STACK = 1000;
    public static final int MAX_SCRIPT_PUSH = 520;
    public static final int MAX_SCRIPT_OPS = 201;
    public static final int MAX_MULTISIG_PUBKEYS = 20;

    // ── Verify flags (common.js) ─────────────────────────────────────────────
    public static final int VERIFY_NONE = 0;
    public static final int VERIFY_MINIMALDATA = 1 << 1;
    public static final int VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 2;
    public static final int VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 3;
    public static final int VERIFY_MINIMALIF = 1 << 4;
    public static final int VERIFY_NULLFAIL = 1 << 5;
    /** Consensus rules, used when validating blocks. */
    public static final int MANDATORY_VERIFY_FLAGS = VERIFY_MINIMALDATA | VERIFY_MINIMALIF | VERIFY_NULLFAIL;
    /** Mempool policy. */
    public static final int STANDARD_VERIFY_FLAGS = MANDATORY_VERIFY_FLAGS
            | VERIFY_DISCOURAGE_UPGRADABLE_NOPS | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;

    // ── Opcodes ──────────────────────────────────────────────────────────────
    static final int OP_0 = 0x00, OP_PUSHDATA1 = 0x4c, OP_PUSHDATA2 = 0x4d, OP_PUSHDATA4 = 0x4e,
            OP_1NEGATE = 0x4f, OP_1 = 0x51, OP_16 = 0x60, OP_NOP = 0x61, OP_IF = 0x63, OP_NOTIF = 0x64,
            OP_ELSE = 0x67, OP_ENDIF = 0x68, OP_VERIFY = 0x69, OP_RETURN = 0x6a,
            OP_TOALTSTACK = 0x6b, OP_FROMALTSTACK = 0x6c, OP_2DROP = 0x6d, OP_2DUP = 0x6e, OP_3DUP = 0x6f,
            OP_2OVER = 0x70, OP_2ROT = 0x71, OP_2SWAP = 0x72, OP_IFDUP = 0x73, OP_DEPTH = 0x74,
            OP_DROP = 0x75, OP_DUP = 0x76, OP_NIP = 0x77, OP_OVER = 0x78, OP_PICK = 0x79, OP_ROLL = 0x7a,
            OP_ROT = 0x7b, OP_SWAP = 0x7c, OP_TUCK = 0x7d, OP_SIZE = 0x82, OP_EQUAL = 0x87,
            OP_EQUALVERIFY = 0x88, OP_1ADD = 0x8b, OP_1SUB = 0x8c, OP_NEGATE = 0x8f, OP_ABS = 0x90,
            OP_NOT = 0x91, OP_0NOTEQUAL = 0x92, OP_ADD = 0x93, OP_SUB = 0x94, OP_BOOLAND = 0x9a,
            OP_BOOLOR = 0x9b, OP_NUMEQUAL = 0x9c, OP_NUMEQUALVERIFY = 0x9d, OP_NUMNOTEQUAL = 0x9e,
            OP_LESSTHAN = 0x9f, OP_GREATERTHAN = 0xa0, OP_LESSTHANOREQUAL = 0xa1,
            OP_GREATERTHANOREQUAL = 0xa2, OP_MIN = 0xa3, OP_MAX = 0xa4, OP_WITHIN = 0xa5,
            OP_RIPEMD160 = 0xa6, OP_SHA1 = 0xa7, OP_SHA256 = 0xa8, OP_HASH160 = 0xa9, OP_HASH256 = 0xaa,
            OP_CODESEPARATOR = 0xab, OP_CHECKSIG = 0xac, OP_CHECKSIGVERIFY = 0xad,
            OP_CHECKMULTISIG = 0xae, OP_CHECKMULTISIGVERIFY = 0xaf, OP_NOP1 = 0xb0,
            OP_CHECKLOCKTIMEVERIFY = 0xb1, OP_CHECKSEQUENCEVERIFY = 0xb2, OP_NOP4 = 0xb3,
            OP_NOP10 = 0xb9, OP_BLAKE160 = 0xc0, OP_BLAKE256 = 0xc1, OP_SHA3 = 0xc2, OP_KECCAK = 0xc3,
            OP_TYPE = 0xd0;

    /** A script failure (hsd ScriptError). {@code code} is hsd's error code string. */
    public static final class ScriptException extends Exception {
        public final String code;
        public ScriptException(String code) { super(code, null, false, false); this.code = code; }
    }

    // ── Decoded script ───────────────────────────────────────────────────────

    /** One decoded opcode. value == -1 marks a parse error (truncated push). */
    static final class Op {
        final int value;
        final byte[] data;   // null when not a push (OP_0 and 0x4f.. have no data)
        final int start;     // offset of this op in the raw script
        Op(int value, byte[] data, int start) { this.value = value; this.data = data; this.start = start; }
    }

    static final class Code {
        final byte[] raw;
        final List<Op> ops = new ArrayList<>();
        Code(byte[] raw) {
            this.raw = raw;
            int p = 0;
            while (p < raw.length) {
                int start = p;
                int v = raw[p++] & 0xff;
                if (v >= 0x01 && v <= 0x4e) {
                    int size;
                    if (v == OP_PUSHDATA1) {
                        if (raw.length - p < 1) { ops.add(new Op(-1, null, start)); break; }
                        size = raw[p++] & 0xff;
                    } else if (v == OP_PUSHDATA2) {
                        if (raw.length - p < 2) { ops.add(new Op(-1, null, start)); break; }
                        size = (raw[p] & 0xff) | ((raw[p + 1] & 0xff) << 8); p += 2;
                    } else if (v == OP_PUSHDATA4) {
                        if (raw.length - p < 4) { ops.add(new Op(-1, null, start)); break; }
                        long s = (raw[p] & 0xffL) | ((raw[p + 1] & 0xffL) << 8)
                                | ((raw[p + 2] & 0xffL) << 16) | ((raw[p + 3] & 0xffL) << 24);
                        p += 4;
                        if (s > raw.length - p) { ops.add(new Op(-1, null, start)); break; }
                        size = (int) s;
                    } else {
                        size = v;
                    }
                    if (raw.length - p < size) { ops.add(new Op(-1, null, start)); break; }
                    ops.add(new Op(v, Arrays.copyOfRange(raw, p, p + size), start));
                    p += size;
                } else {
                    ops.add(new Op(v, null, start));
                }
            }
        }

        /** hsd getSubscript(index). */
        byte[] subscript(int index) {
            if (index == 0) return raw;
            if (index >= ops.size()) return new byte[0];
            int end = raw.length;
            for (int i = index; i < ops.size(); i++) {
                if (ops.get(i).value == -1) { end = ops.get(i).start; break; }
            }
            return Arrays.copyOfRange(raw, ops.get(index).start, end);
        }

        /** hsd Script.getSigops(). */
        int sigops() {
            int total = 0, lastOp = -1;
            for (Op op : ops) {
                if (op.value == -1) break;
                switch (op.value) {
                    case OP_CHECKSIG: case OP_CHECKSIGVERIFY: total += 1; break;
                    case OP_CHECKMULTISIG: case OP_CHECKMULTISIGVERIFY:
                        if (lastOp >= OP_1 && lastOp <= OP_16) total += lastOp - 0x50;
                        else total += MAX_MULTISIG_PUBKEYS;
                        break;
                    default: break;
                }
                lastOp = op.value;
            }
            return total;
        }
    }

    // ── Script numbers ───────────────────────────────────────────────────────

    static boolean isMinimalNum(byte[] d) {
        if (d.length == 0) return true;
        if ((d[d.length - 1] & 0x7f) == 0) {
            if (d.length == 1) return false;
            if ((d[d.length - 2] & 0x80) == 0) return false;
        }
        return true;
    }

    static long decodeNum(byte[] d, boolean minimal, int limit) throws ScriptException {
        if (limit >= 0 && d.length > limit) throw new ScriptException("UNKNOWN_ERROR");
        if (minimal && !isMinimalNum(d)) throw new ScriptException("UNKNOWN_ERROR");
        if (d.length == 0) return 0;
        long v = 0;
        for (int i = 0; i < d.length; i++) v |= (d[i] & 0xffL) << (8 * i);
        if ((d[d.length - 1] & 0x80) != 0) {
            v &= ~(0x80L << (8 * (d.length - 1)));
            v = -v;
        }
        return v;
    }

    static byte[] encodeNum(long n) {
        if (n == 0) return new byte[0];
        boolean neg = n < 0;
        long a = neg ? -n : n;
        byte[] tmp = new byte[9];
        int len = 0;
        while (a != 0) { tmp[len++] = (byte) (a & 0xff); a >>>= 8; }
        if ((tmp[len - 1] & 0x80) != 0) tmp[len++] = (byte) (neg ? 0x80 : 0x00);
        else if (neg) tmp[len - 1] |= (byte) 0x80;
        return Arrays.copyOf(tmp, len);
    }

    private static final byte[] EMPTY = new byte[0];
    private static final byte[] ONE = {1};

    static byte[] fromBool(boolean b) { return b ? ONE : EMPTY; }

    static boolean toBool(byte[] item) {
        for (int i = 0; i < item.length; i++) {
            if (item[i] != 0) {
                if (i == item.length - 1 && (item[i] & 0xff) == 0x80) return false;
                return true;
            }
        }
        return false;
    }

    // ── Hash helpers ─────────────────────────────────────────────────────────

    private static byte[] md(String alg, byte[] d) {
        try { return MessageDigest.getInstance(alg).digest(d); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    // ── Key / signature encoding (common.js) ─────────────────────────────────

    static boolean isKeyEncoding(byte[] key) {
        return key.length == 33 && (key[0] == 0x02 || key[0] == 0x03);
    }

    static boolean isSignatureEncoding(byte[] sig) {
        if (sig.length != 65) return false;
        int type = sig[64] & 0xff;
        type &= ~TxVerify.SIGHASH_NOINPUT;
        type &= ~TxVerify.SIGHASH_ANYONECANPAY;
        if (type < TxVerify.SIGHASH_ALL || type > TxVerify.SIGHASH_SINGLEREVERSE) return false;
        return Secp256k1.isLowS(Arrays.copyOf(sig, 64));
    }

    private static boolean checksig(byte[] msg, byte[] sig, byte[] key) {
        try { return Secp256k1.verifyRaw(msg, Arrays.copyOf(sig, sig.length - 1), key); }
        catch (RuntimeException e) { return false; }
    }

    // ── Stack helpers ────────────────────────────────────────────────────────

    private static byte[] get(List<byte[]> s, int idx) {
        int i = idx < 0 ? s.size() + idx : idx;
        return s.get(i);
    }

    private static byte[] pop(List<byte[]> s) { return s.remove(s.size() - 1); }

    private static void pushInt(List<byte[]> s, long n) { s.add(encodeNum(n)); }

    private static int getInt(List<byte[]> s, int idx, boolean minimal, int limit) throws ScriptException {
        return (int) decodeNum(get(s, idx), minimal, limit);
    }

    // ── Execution ────────────────────────────────────────────────────────────

    /** hsd Script.execute(). Runs {@code code} against {@code stack}. */
    static void execute(Code code, List<byte[]> stack, int flags, TxParser.ParsedTx tx, int index, long value)
            throws ScriptException {
        if (code.raw.length > MAX_SCRIPT_SIZE) throw new ScriptException("SCRIPT_SIZE");

        List<Boolean> state = new ArrayList<>();
        List<byte[]> alt = new ArrayList<>();
        int lastSep = 0, opCount = 0, negate = 0;
        boolean minimal = (flags & VERIFY_MINIMALDATA) != 0;

        for (int ip = 0; ip < code.ops.size(); ip++) {
            Op op = code.ops.get(ip);
            int ov = op.value;

            if (ov == -1) throw new ScriptException("BAD_OPCODE");
            if (op.data != null && op.data.length > MAX_SCRIPT_PUSH) throw new ScriptException("PUSH_SIZE");
            if (ov > OP_16 && ++opCount > MAX_SCRIPT_OPS) throw new ScriptException("OP_COUNT");
            if (isDisabled(ov)) throw new ScriptException("DISABLED_OPCODE");

            boolean isBranch = ov >= OP_IF && ov <= OP_ENDIF;
            if (negate != 0 && !isBranch) {
                if (stack.size() + alt.size() > MAX_SCRIPT_STACK) throw new ScriptException("STACK_SIZE");
                continue;
            }

            if (op.data != null) {
                if (minimal && !isMinimalPush(op)) throw new ScriptException("MINIMALDATA");
                stack.add(op.data);
                if (stack.size() + alt.size() > MAX_SCRIPT_STACK) throw new ScriptException("STACK_SIZE");
                continue;
            }

            switch (ov) {
                case OP_0: pushInt(stack, 0); break;
                case OP_1NEGATE: pushInt(stack, -1); break;
                case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
                case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: case 0x60:
                    pushInt(stack, ov - 0x50); break;
                case OP_NOP: break;
                case OP_TYPE: {
                    if (tx == null) throw new ScriptException("UNKNOWN_ERROR");
                    if (index >= tx.outputs.size()) { pushInt(stack, 0); break; }
                    pushInt(stack, tx.outputs.get(index).covenant.type);
                    break;
                }
                case OP_CHECKLOCKTIMEVERIFY: {
                    if (tx == null) throw new ScriptException("UNKNOWN_ERROR");
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    long num = decodeNum(get(stack, -1), minimal, 5);
                    if (num < 0) throw new ScriptException("NEGATIVE_LOCKTIME");
                    if (!verifyLocktime(tx, index, num)) throw new ScriptException("UNSATISFIED_LOCKTIME");
                    break;
                }
                case OP_CHECKSEQUENCEVERIFY: {
                    if (tx == null) throw new ScriptException("UNKNOWN_ERROR");
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    long num = decodeNum(get(stack, -1), minimal, 5);
                    if (num < 0) throw new ScriptException("NEGATIVE_LOCKTIME");
                    if (!verifySequence(tx, index, num)) throw new ScriptException("UNSATISFIED_LOCKTIME");
                    break;
                }
                case OP_NOP1: case OP_NOP4: case 0xb4: case 0xb5: case 0xb6: case 0xb7: case 0xb8: case OP_NOP10: {
                    if ((flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0)
                        throw new ScriptException("DISCOURAGE_UPGRADABLE_NOPS");
                    break;
                }
                case OP_IF: case OP_NOTIF: {
                    boolean val = false;
                    if (negate == 0) {
                        if (stack.size() < 1) throw new ScriptException("UNBALANCED_CONDITIONAL");
                        if ((flags & VERIFY_MINIMALIF) != 0) {
                            byte[] item = get(stack, -1);
                            if (item.length > 1) throw new ScriptException("MINIMALIF");
                            if (item.length == 1 && item[0] != 1) throw new ScriptException("MINIMALIF");
                        }
                        val = toBool(get(stack, -1));
                        if (ov == OP_NOTIF) val = !val;
                        pop(stack);
                    }
                    state.add(val);
                    if (!val) negate += 1;
                    break;
                }
                case OP_ELSE: {
                    if (state.isEmpty()) throw new ScriptException("UNBALANCED_CONDITIONAL");
                    int last = state.size() - 1;
                    state.set(last, !state.get(last));
                    if (!state.get(last)) negate += 1; else negate -= 1;
                    break;
                }
                case OP_ENDIF: {
                    if (state.isEmpty()) throw new ScriptException("UNBALANCED_CONDITIONAL");
                    if (!state.remove(state.size() - 1)) negate -= 1;
                    break;
                }
                case OP_VERIFY: {
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    if (!toBool(get(stack, -1))) throw new ScriptException("VERIFY");
                    pop(stack);
                    break;
                }
                case OP_RETURN: throw new ScriptException("OP_RETURN");
                case OP_TOALTSTACK: {
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    alt.add(pop(stack));
                    break;
                }
                case OP_FROMALTSTACK: {
                    if (alt.isEmpty()) throw new ScriptException("INVALID_ALTSTACK_OPERATION");
                    stack.add(alt.remove(alt.size() - 1));
                    break;
                }
                case OP_2DROP: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    pop(stack); pop(stack);
                    break;
                }
                case OP_2DUP: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] v1 = get(stack, -2), v2 = get(stack, -1);
                    stack.add(v1); stack.add(v2);
                    break;
                }
                case OP_3DUP: {
                    if (stack.size() < 3) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] v1 = get(stack, -3), v2 = get(stack, -2), v3 = get(stack, -1);
                    stack.add(v1); stack.add(v2); stack.add(v3);
                    break;
                }
                case OP_2OVER: {
                    if (stack.size() < 4) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] v1 = get(stack, -4), v2 = get(stack, -3);
                    stack.add(v1); stack.add(v2);
                    break;
                }
                case OP_2ROT: {
                    if (stack.size() < 6) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] v1 = get(stack, -6), v2 = get(stack, -5);
                    int s = stack.size() - 6;
                    stack.remove(s); stack.remove(s);
                    stack.add(v1); stack.add(v2);
                    break;
                }
                case OP_2SWAP: {
                    if (stack.size() < 4) throw new ScriptException("INVALID_STACK_OPERATION");
                    swap(stack, -4, -2); swap(stack, -3, -1);
                    break;
                }
                case OP_IFDUP: {
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    if (toBool(get(stack, -1))) stack.add(get(stack, -1));
                    break;
                }
                case OP_DEPTH: pushInt(stack, stack.size()); break;
                case OP_DROP: {
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    pop(stack);
                    break;
                }
                case OP_DUP: {
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    stack.add(get(stack, -1));
                    break;
                }
                case OP_NIP: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    stack.remove(stack.size() - 2);
                    break;
                }
                case OP_OVER: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    stack.add(get(stack, -2));
                    break;
                }
                case OP_PICK: case OP_ROLL: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    int num = getInt(stack, -1, minimal, 4);
                    pop(stack);
                    if (num < 0 || num >= stack.size()) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] val = get(stack, -num - 1);
                    if (ov == OP_ROLL) stack.remove(stack.size() - num - 1);
                    stack.add(val);
                    break;
                }
                case OP_ROT: {
                    if (stack.size() < 3) throw new ScriptException("INVALID_STACK_OPERATION");
                    swap(stack, -3, -2); swap(stack, -2, -1);
                    break;
                }
                case OP_SWAP: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    swap(stack, -2, -1);
                    break;
                }
                case OP_TUCK: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    stack.add(stack.size() - 2, get(stack, -1));
                    break;
                }
                case OP_SIZE: {
                    if (stack.size() < 1) throw new ScriptException("INVALID_STACK_OPERATION");
                    pushInt(stack, get(stack, -1).length);
                    break;
                }
                case OP_EQUAL: case OP_EQUALVERIFY: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    boolean res = Arrays.equals(get(stack, -2), get(stack, -1));
                    pop(stack); pop(stack);
                    stack.add(fromBool(res));
                    if (ov == OP_EQUALVERIFY) {
                        if (!res) throw new ScriptException("EQUALVERIFY");
                        pop(stack);
                    }
                    break;
                }
                case OP_1ADD: case OP_1SUB: case OP_NEGATE: case OP_ABS: case OP_NOT: case OP_0NOTEQUAL: {
                    if (stack.size() < 1) throw new ScriptException("INVALID_STACK_OPERATION");
                    long num = decodeNum(get(stack, -1), minimal, 4);
                    switch (ov) {
                        case OP_1ADD: num += 1; break;
                        case OP_1SUB: num -= 1; break;
                        case OP_NEGATE: num = -num; break;
                        case OP_ABS: num = Math.abs(num); break;
                        case OP_NOT: num = num == 0 ? 1 : 0; break;
                        default: num = num != 0 ? 1 : 0; break;
                    }
                    pop(stack);
                    stack.add(encodeNum(num));
                    break;
                }
                case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR: case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY: case OP_NUMNOTEQUAL: case OP_LESSTHAN: case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL: case OP_MIN: case OP_MAX: {
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    long n1 = decodeNum(get(stack, -2), minimal, 4);
                    long n2 = decodeNum(get(stack, -1), minimal, 4);
                    long num;
                    switch (ov) {
                        case OP_ADD: num = n1 + n2; break;
                        case OP_SUB: num = n1 - n2; break;
                        case OP_BOOLAND: num = (n1 != 0 && n2 != 0) ? 1 : 0; break;
                        case OP_BOOLOR: num = (n1 != 0 || n2 != 0) ? 1 : 0; break;
                        case OP_NUMEQUAL: case OP_NUMEQUALVERIFY: num = n1 == n2 ? 1 : 0; break;
                        case OP_NUMNOTEQUAL: num = n1 != n2 ? 1 : 0; break;
                        case OP_LESSTHAN: num = n1 < n2 ? 1 : 0; break;
                        case OP_GREATERTHAN: num = n1 > n2 ? 1 : 0; break;
                        case OP_LESSTHANOREQUAL: num = n1 <= n2 ? 1 : 0; break;
                        case OP_GREATERTHANOREQUAL: num = n1 >= n2 ? 1 : 0; break;
                        case OP_MIN: num = Math.min(n1, n2); break;
                        default: num = Math.max(n1, n2); break;
                    }
                    pop(stack); pop(stack);
                    stack.add(encodeNum(num));
                    if (ov == OP_NUMEQUALVERIFY) {
                        if (!toBool(get(stack, -1))) throw new ScriptException("NUMEQUALVERIFY");
                        pop(stack);
                    }
                    break;
                }
                case OP_WITHIN: {
                    if (stack.size() < 3) throw new ScriptException("INVALID_STACK_OPERATION");
                    long n1 = decodeNum(get(stack, -3), minimal, 4);
                    long n2 = decodeNum(get(stack, -2), minimal, 4);
                    long n3 = decodeNum(get(stack, -1), minimal, 4);
                    boolean val = n2 <= n1 && n1 < n3;
                    pop(stack); pop(stack); pop(stack);
                    stack.add(fromBool(val));
                    break;
                }
                case OP_RIPEMD160: case OP_SHA1: case OP_SHA256: case OP_HASH160: case OP_HASH256:
                case OP_BLAKE160: case OP_BLAKE256: case OP_SHA3: case OP_KECCAK: {
                    if (stack.isEmpty()) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] d = pop(stack);
                    byte[] h;
                    switch (ov) {
                        case OP_RIPEMD160: h = Ripemd160.hash(d); break;
                        case OP_SHA1: h = md("SHA-1", d); break;
                        case OP_SHA256: h = md("SHA-256", d); break;
                        case OP_HASH160: h = Ripemd160.hash(md("SHA-256", d)); break;
                        case OP_HASH256: h = md("SHA-256", md("SHA-256", d)); break;
                        case OP_BLAKE160: h = Blake2b.hash(d, 20); break;
                        case OP_BLAKE256: h = Blake2b.hash256(d); break;
                        case OP_SHA3: h = md("SHA3-256", d); break;
                        default: h = Keccak256.hash(d); break;
                    }
                    stack.add(h);
                    break;
                }
                case OP_CODESEPARATOR: lastSep = ip + 1; break;
                case OP_CHECKSIG: case OP_CHECKSIGVERIFY: {
                    if (tx == null) throw new ScriptException("UNKNOWN_ERROR");
                    if (stack.size() < 2) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] sig = get(stack, -2), key = get(stack, -1);
                    byte[] subscript = code.subscript(lastSep);
                    validateSignature(sig);
                    validateKey(key);
                    boolean res = false;
                    if (sig.length > 0) {
                        int type = sig[sig.length - 1] & 0xff;
                        byte[] hash = TxVerify.computeSignatureHash(tx, index, subscript, value, type);
                        res = checksig(hash, sig, key);
                    }
                    if (!res && (flags & VERIFY_NULLFAIL) != 0 && sig.length != 0)
                        throw new ScriptException("NULLFAIL");
                    pop(stack); pop(stack);
                    stack.add(fromBool(res));
                    if (ov == OP_CHECKSIGVERIFY) {
                        if (!res) throw new ScriptException("CHECKSIGVERIFY");
                        pop(stack);
                    }
                    break;
                }
                case OP_CHECKMULTISIG: case OP_CHECKMULTISIGVERIFY: {
                    if (tx == null) throw new ScriptException("UNKNOWN_ERROR");
                    int i = 1;
                    if (stack.size() < i) throw new ScriptException("INVALID_STACK_OPERATION");
                    int n = getInt(stack, -i, minimal, 4);
                    int okey = n + 2;
                    if (n < 0 || n > MAX_MULTISIG_PUBKEYS) throw new ScriptException("PUBKEY_COUNT");
                    opCount += n;
                    if (opCount > MAX_SCRIPT_OPS) throw new ScriptException("OP_COUNT");
                    i += 1;
                    int ikey = i;
                    i += n;
                    if (stack.size() < i) throw new ScriptException("INVALID_STACK_OPERATION");
                    int m = getInt(stack, -i, minimal, 4);
                    if (m < 0 || m > n) throw new ScriptException("SIG_COUNT");
                    i += 1;
                    int isig = i;
                    i += m;
                    if (stack.size() < i) throw new ScriptException("INVALID_STACK_OPERATION");
                    byte[] subscript = code.subscript(lastSep);
                    boolean res = true;
                    while (res && m > 0) {
                        byte[] sig = get(stack, -isig), key = get(stack, -ikey);
                        validateSignature(sig);
                        validateKey(key);
                        if (sig.length > 0) {
                            int type = sig[sig.length - 1] & 0xff;
                            byte[] hash = TxVerify.computeSignatureHash(tx, index, subscript, value, type);
                            if (checksig(hash, sig, key)) { isig += 1; m -= 1; }
                        }
                        ikey += 1;
                        n -= 1;
                        if (m > n) res = false;
                    }
                    while (i > 1) {
                        if (!res && (flags & VERIFY_NULLFAIL) != 0) {
                            if (okey == 0 && get(stack, -1).length != 0) throw new ScriptException("NULLFAIL");
                        }
                        if (okey > 0) okey -= 1;
                        pop(stack);
                        i -= 1;
                    }
                    if (stack.size() < 1) throw new ScriptException("INVALID_STACK_OPERATION");
                    if (get(stack, -1).length != 0) throw new ScriptException("SIG_NULLDUMMY");
                    pop(stack);
                    stack.add(fromBool(res));
                    if (ov == OP_CHECKMULTISIGVERIFY) {
                        if (!res) throw new ScriptException("CHECKMULTISIGVERIFY");
                        pop(stack);
                    }
                    break;
                }
                default:
                    throw new ScriptException("BAD_OPCODE");
            }

            if (stack.size() + alt.size() > MAX_SCRIPT_STACK) throw new ScriptException("STACK_SIZE");
        }

        if (!state.isEmpty()) throw new ScriptException("UNBALANCED_CONDITIONAL");
    }

    private static void swap(List<byte[]> s, int i1, int i2) {
        int a = i1 < 0 ? s.size() + i1 : i1, b = i2 < 0 ? s.size() + i2 : i2;
        byte[] t = s.get(a); s.set(a, s.get(b)); s.set(b, t);
    }

    private static boolean isDisabled(int v) {
        switch (v) {
            case 0x7e: case 0x7f: case 0x80: case 0x81:           // CAT SUBSTR LEFT RIGHT
            case 0x83: case 0x84: case 0x85: case 0x86:           // INVERT AND OR XOR
            case 0x8d: case 0x8e: case 0x95: case 0x96:           // 2MUL 2DIV MUL DIV
            case 0x97: case 0x98: case 0x99:                      // MOD LSHIFT RSHIFT
                return true;
            default: return false;
        }
    }

    /** hsd Opcode.isMinimal() (only called for push ops). */
    private static boolean isMinimalPush(Op op) {
        byte[] d = op.data;
        if (d.length == 1) {
            if ((d[0] & 0xff) == 0x81) return false;
            if ((d[0] & 0xff) >= 1 && (d[0] & 0xff) <= 16) return false;
        }
        if (d.length <= 0x4b) return op.value == d.length;
        if (d.length <= 0xff) return op.value == OP_PUSHDATA1;
        if (d.length <= 0xffff) return op.value == OP_PUSHDATA2;
        return true;
    }

    private static void validateSignature(byte[] sig) throws ScriptException {
        if (sig.length == 0) return;
        if (!isSignatureEncoding(sig)) throw new ScriptException("SIG_ENCODING");
    }

    private static void validateKey(byte[] key) throws ScriptException {
        if (!isKeyEncoding(key)) throw new ScriptException("PUBKEY_ENCODING");
    }

    // ── Locktime / sequence (tx.js, consensus.js) ────────────────────────────

    private static final int LOCKTIME_FLAG = 0x80000000;
    private static final int LOCKTIME_MASK = 0x7fffffff;
    private static final int SEQUENCE_DISABLE_FLAG = 0x80000000;
    private static final int SEQUENCE_TYPE_FLAG = 1 << 22;
    private static final int SEQUENCE_MASK = 0x0000ffff;

    static boolean verifyLocktime(TxParser.ParsedTx tx, int index, long predicateL) {
        int predicate = (int) predicateL; // JS bitwise ops truncate to 32 bits
        TxParser.Input input = tx.inputs.get(index);
        if ((tx.locktime & LOCKTIME_FLAG) != (predicate & LOCKTIME_FLAG)) return false;
        if ((predicate & LOCKTIME_MASK) > (tx.locktime & LOCKTIME_MASK)) return false;
        if (input.sequence == 0xffffffff) return false;
        return true;
    }

    static boolean verifySequence(TxParser.ParsedTx tx, int index, long predicateL) {
        int predicate = (int) predicateL;
        TxParser.Input input = tx.inputs.get(index);
        if ((predicate & SEQUENCE_DISABLE_FLAG) != 0) return true;
        if ((input.sequence & SEQUENCE_DISABLE_FLAG) != 0) return false;
        if ((input.sequence & SEQUENCE_TYPE_FLAG) != (predicate & SEQUENCE_TYPE_FLAG)) return false;
        if ((predicate & SEQUENCE_MASK) > (input.sequence & SEQUENCE_MASK)) return false;
        return true;
    }

    // ── Entry points ─────────────────────────────────────────────────────────

    private static byte[] p2pkhScript(byte[] hash20) {
        return TxVerify.buildP2PKHScript(hash20);
    }

    /** hsd Script.verify(): checks input {@code index} of {@code tx} against the coin it spends. */
    public static void verify(TxParser.ParsedTx tx, int index, int addrVersion, byte[] addrHash,
                              long value, int flags) throws ScriptException {
        List<byte[]> witness = tx.inputs.get(index).witness;
        if (addrVersion > 31) throw new ScriptException("UNKNOWN_ERROR");
        if (addrVersion == 31) throw new ScriptException("OP_RETURN");
        if (witness.size() > MAX_SCRIPT_STACK) throw new ScriptException("STACK_SIZE");

        List<byte[]> stack = new ArrayList<>(witness);
        Code redeem;

        if (addrVersion == 0) {
            if (addrHash.length == 32) {
                if (stack.isEmpty()) throw new ScriptException("WITNESS_PROGRAM_WITNESS_EMPTY");
                byte[] witnessScript = pop(stack);
                if (witnessScript.length > MAX_SCRIPT_SIZE) throw new ScriptException("SCRIPT_SIZE");
                if (!Arrays.equals(md("SHA3-256", witnessScript), addrHash))
                    throw new ScriptException("WITNESS_PROGRAM_MISMATCH");
                redeem = new Code(witnessScript);
            } else if (addrHash.length == 20) {
                if (stack.size() != 2) throw new ScriptException("WITNESS_PROGRAM_MISMATCH");
                redeem = new Code(p2pkhScript(addrHash));
            } else {
                throw new ScriptException("WITNESS_PROGRAM_WRONG_LENGTH");
            }
        } else {
            if ((flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) != 0)
                throw new ScriptException("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM");
            return;
        }

        for (byte[] item : stack) {
            if (item.length > MAX_SCRIPT_PUSH) throw new ScriptException("PUSH_SIZE");
        }

        execute(redeem, stack, flags, tx, index, value);

        if (stack.size() != 1 || !toBool(get(stack, -1))) throw new ScriptException("EVAL_FALSE");
    }

    /** True when the input's witness satisfies the coin's address under the given flags. */
    public static boolean verifyInput(TxParser.ParsedTx tx, int index, int addrVersion, byte[] addrHash,
                                      long value, int flags) {
        try {
            verify(tx, index, addrVersion, addrHash, value, flags);
            return true;
        } catch (ScriptException e) {
            return false;
        }
    }

    /** hsd Address.getSigops(witness). */
    public static int getSigops(int addrVersion, byte[] addrHash, List<byte[]> witness) {
        if (addrVersion == 0) {
            if (addrHash.length == 20) return 1;
            if (addrHash.length == 32 && !witness.isEmpty())
                return new Code(witness.get(witness.size() - 1)).sigops();
        }
        return 0;
    }
}