package handshake.node.chain;

import handshake.node.storage.ChainDB;
import handshake.node.util.HexUtil;

import java.util.*;

/**
 * Chain reorganization: switch the main chain from our current branch to a
 * heavier competing branch that forks off at {@code forkHeight}.
 *
 * <h3>Shape</h3>
 * <ol>
 *   <li>{@link #start}: save the old branch's header hashes and the new branch's
 *       headers in the side stores, write the marker, then</li>
 *   <li>DISCONNECT: undo our blocks newest-first ({@link ChainDB#disconnectBlock}),
 *       keeping each raw block in the side store;</li>
 *   <li>HEADERS: roll the header chain back to the fork point and insert the new
 *       branch's headers;</li>
 *   <li>CONNECT: nothing to do here. The normal block download now fetches and
 *       applies the new branch's blocks with full validation;
 *       {@link #onBlockConnected} finishes the reorg when the last one is in.</li>
 *   <li>If a new-branch block is rejected, {@link #restoreOldBranch} undoes the new
 *       blocks and re-applies the old ones from the side store.</li>
 * </ol>
 *
 * <h3>Crash safety</h3>
 * Every step leaves the database consistent (each disconnect is committed with its
 * block-tip change; headers are rolled back only after blocks). The marker records
 * the target, and {@link #resume} re-runs the idempotent DISCONNECT/HEADERS steps
 * after a restart. A crash during CONNECT needs no special handling.
 *
 * Runs on the sync thread only (same thread as block processing).
 */
public final class ReorgExecutor {

    private ReorgExecutor() {}

    static final String META = "reorg_meta";   // forkH|phase|oldBlockTip|oldHeaderTip
    static final String OLD  = "reorg_old";    // csv hex hashes of OUR headers forkH+1..oldHeaderTip
    static final String NEW  = "reorg_new";    // csv hex hashes of the new branch, in order
    static final String INVALID = "reorg_invalid"; // csv hex hashes of blocks that failed validation

    public static final String PHASE_DISCONNECT = "DISCONNECT";
    public static final String PHASE_HEADERS = "HEADERS";
    public static final String PHASE_CONNECT = "CONNECT";

    /** Transactions from disconnected blocks, re-offered to the mempool when the reorg completes. */
    private static final List<byte[]> pendingReadd = new ArrayList<>();

    // ── marker helpers ────────────────────────────────────────────────────────

    public static boolean inProgress(ChainDB db) { return db.getMeta(META) != null; }

    private record State(int forkH, String phase, int oldBlockTip, int oldHeaderTip) {}

    private static State state(ChainDB db) {
        String m = db.getMeta(META);
        if (m == null) return null;
        String[] p = m.split("\\|");
        return new State(Integer.parseInt(p[0]), p[1], Integer.parseInt(p[2]), Integer.parseInt(p[3]));
    }

    private static void setState(ChainDB db, State s) {
        db.putMeta(META, s.forkH + "|" + s.phase + "|" + s.oldBlockTip + "|" + s.oldHeaderTip);
    }

    private static List<byte[]> hashes(ChainDB db, String key) {
        String v = db.getMeta(key);
        List<byte[]> out = new ArrayList<>();
        if (v == null || v.isEmpty()) return out;
        for (String s : v.split(",")) out.add(HexUtil.decode(s));
        return out;
    }

    private static String csv(List<byte[]> hs) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hs.size(); i++) { if (i > 0) sb.append(','); sb.append(HexUtil.encode(hs.get(i))); }
        return sb.toString();
    }

    // ── invalid-branch memory ─────────────────────────────────────────────────

    public static boolean isKnownInvalid(ChainDB db, byte[] hash) {
        String v = db.getMeta(INVALID);
        return v != null && v.contains(HexUtil.encode(hash));
    }

    private static void markInvalid(ChainDB db, byte[] hash) {
        String v = db.getMeta(INVALID);
        List<String> l = new ArrayList<>();
        if (v != null && !v.isEmpty()) l.addAll(Arrays.asList(v.split(",")));
        l.add(HexUtil.encode(hash));
        while (l.size() > 50) l.remove(0);
        db.putMeta(INVALID, String.join(",", l));
    }

    // ── eligibility ───────────────────────────────────────────────────────────

    /** True if we can undo every block above {@code forkH} (within retention, undo data present). */
    public static boolean canReorg(ChainDB db, int forkH) {
        int blockTip = db.getBlockTip();
        if (blockTip - forkH > ChainDB.UNDO_RETENTION) return false;
        for (int h = blockTip; h > forkH; h--) {
            if (!db.hasUndo(h)) return false;
        }
        return true;
    }

    // ── execution ─────────────────────────────────────────────────────────────

    /**
     * Begins a reorganization to {@code newBranch} (headers forkH+1, forkH+2, ...,
     * already validated for links, PoW and difficulty, and heavier than ours).
     */
    public static void start(ChainDB db, int forkH, List<byte[]> newBranch, ListenerHook hook) {
        if (inProgress(db)) throw new IllegalStateException("a reorg is already in progress");
        int oldHeaderTip = db.getHeaderTip();
        int oldBlockTip = db.getBlockTip();
        List<byte[]> oldHashes = new ArrayList<>();
        for (int h = forkH + 1; h <= oldHeaderTip; h++) {
            byte[] hd = db.getHeader(h);
            if (hd == null) break;
            oldHashes.add(HeaderUtil.hash(hd));
            db.putSideHeader(HeaderUtil.hash(hd), hd);
        }
        List<byte[]> newHashes = new ArrayList<>();
        for (byte[] hd : newBranch) {
            byte[] hash = HeaderUtil.hash(hd);
            newHashes.add(hash);
            db.putSideHeader(hash, hd);
        }
        db.putMeta(OLD, csv(oldHashes));
        db.putMeta(NEW, csv(newHashes));
        setState(db, new State(forkH, PHASE_DISCONNECT, oldBlockTip, oldHeaderTip));
        db.commit();
        System.out.printf("[Reorg] START: fork at %d, undoing %d block(s) (tip %d), adopting %d header(s).%n",
                forkH, Math.max(0, oldBlockTip - forkH), oldBlockTip, newBranch.size());
        run(db, hook);
    }

    /** Notification sink so the caller can tell listeners / mempool about undone blocks. */
    public interface ListenerHook {
        void blockDisconnected(int height, byte[] hash, byte[] rawBlock);
        void reorgCompleted(List<byte[]> disconnectedTxs);
        ListenerHook NONE = new ListenerHook() {
            public void blockDisconnected(int height, byte[] hash, byte[] rawBlock) {}
            public void reorgCompleted(List<byte[]> disconnectedTxs) {}
        };
    }

    /** Re-runs an interrupted DISCONNECT/HEADERS phase (call at startup / start of a sync cycle). */
    public static void resume(ChainDB db, ListenerHook hook) {
        State s = state(db);
        if (s == null) return;
        if (PHASE_CONNECT.equals(s.phase)) return; // normal sync continues the job
        System.out.println("[Reorg] Resuming interrupted reorganization at phase " + s.phase);
        run(db, hook);
    }

    private static void run(ChainDB db, ListenerHook hook) {
        State s = state(db);
        if (s == null) return;
        int forkH = s.forkH;

        if (PHASE_DISCONNECT.equals(s.phase)) {
            for (int h = db.getBlockTip(); h > forkH; h--) {
                byte[] hd = db.getHeader(h);
                byte[] raw = db.getBlock(h);
                byte[] hash = hd != null ? HeaderUtil.hash(hd) : null;
                if (raw != null && hash != null) {
                    db.putSideBlock(hash, raw);
                    collectTxs(raw);
                }
                db.disconnectBlock(h); // commits
                if (hook != null && hash != null && raw != null) hook.blockDisconnected(h, hash, raw);
            }
            s = new State(forkH, PHASE_HEADERS, s.oldBlockTip, s.oldHeaderTip);
            setState(db, s);
            db.commit();
        }

        if (PHASE_HEADERS.equals(s.phase)) {
            List<byte[]> newHashes = hashes(db, NEW);
            byte[] first = db.getHeader(forkH + 1);
            boolean alreadySwapped = first != null && !newHashes.isEmpty()
                    && Arrays.equals(HeaderUtil.hash(first), newHashes.get(0));
            if (!alreadySwapped) {
                db.rollbackHeadersTo(forkH);
                List<byte[]> hs = new ArrayList<>();
                for (byte[] h : newHashes) hs.add(db.getSideHeader(h));
                db.insertHeaders(hs, forkH + 1);
            }
            s = new State(forkH, PHASE_CONNECT, s.oldBlockTip, s.oldHeaderTip);
            setState(db, s);
            db.commit();
            System.out.printf("[Reorg] Headers switched; waiting for blocks %d..%d of the new branch.%n",
                    forkH + 1, forkH + newHashes.size());
        }
    }

    private static void collectTxs(byte[] rawBlock) {
        try {
            List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
            for (int i = 1; i < txs.size(); i++) { // skip coinbase
                pendingReadd.add(Arrays.copyOf(txs.get(i).raw, txs.get(i).raw.length));
            }
        } catch (Exception ignored) {}
    }

    /** Call after every block connected by normal sync. Finishes the reorg when the new branch is fully applied. */
    public static void onBlockConnected(ChainDB db, int height, ListenerHook hook) {
        State s = state(db);
        if (s == null || !PHASE_CONNECT.equals(s.phase)) return;
        int newTipHeight = s.forkH + hashes(db, NEW).size();
        if (height < newTipHeight) return;
        System.out.printf("[Reorg] COMPLETE: new branch applied through height %d.%n", height);
        clear(db);
        List<byte[]> txs = new ArrayList<>(pendingReadd);
        pendingReadd.clear();
        if (hook != null) hook.reorgCompleted(txs);
    }

    /** True while a reorg's CONNECT phase is waiting for new-branch blocks (a failure then triggers a restore). */
    public static boolean connecting(ChainDB db) {
        State s = state(db);
        return s != null && PHASE_CONNECT.equals(s.phase);
    }

    /**
     * A new-branch block failed validation: undo whatever of the new branch was
     * applied and put the old branch back (headers, then blocks from the side
     * store). The failing block's hash is remembered so the branch isn't retried.
     *
     * @throws IllegalStateException if the old branch cannot be fully restored (local state damaged)
     */
    public static void restoreOldBranch(ChainDB db, byte[] failedBlockHash, ListenerHook hook) {
        State s = state(db);
        if (s == null) return;
        System.err.println("[Reorg] New branch failed validation -- restoring the previous chain.");
        if (failedBlockHash != null) markInvalid(db, failedBlockHash);
        int forkH = s.forkH;
        for (int h = db.getBlockTip(); h > forkH; h--) {
            byte[] hd = db.getHeader(h);
            byte[] raw = db.getBlock(h);
            byte[] hash = hd != null ? HeaderUtil.hash(hd) : null;
            db.disconnectBlock(h);
            if (hook != null && hash != null && raw != null) hook.blockDisconnected(h, hash, raw);
        }
        db.rollbackHeadersTo(forkH);
        List<byte[]> oldHashes = hashes(db, OLD);
        List<byte[]> oldHeaders = new ArrayList<>();
        for (byte[] h : oldHashes) {
            byte[] hd = db.getSideHeader(h);
            if (hd == null) throw new IllegalStateException("missing saved header while restoring old branch");
            oldHeaders.add(hd);
        }
        db.insertHeaders(oldHeaders, forkH + 1);
        for (int h = forkH + 1; h <= s.oldBlockTip; h++) {
            byte[] hash = oldHashes.get(h - forkH - 1);
            byte[] raw = db.getSideBlock(hash);
            if (raw == null) throw new IllegalStateException("missing saved block " + h + " while restoring old branch");
            BlockProcessor.Result r = BlockProcessor.process(raw, h, db, null, 0);
            if (r != BlockProcessor.Result.VALID) {
                throw new IllegalStateException("old block " + h + " no longer applies (" + r + ")");
            }
            db.saveBlock(raw, h);
            db.setBlockTip(h);
            db.commit();
        }
        clear(db);
        pendingReadd.clear();
        System.out.printf("[Reorg] Previous chain restored through height %d.%n", s.oldBlockTip);
    }

    private static void clear(ChainDB db) {
        db.removeMeta(META);
        db.removeMeta(OLD);
        db.removeMeta(NEW);
        db.clearSideStores();
        db.commit();
    }
}
