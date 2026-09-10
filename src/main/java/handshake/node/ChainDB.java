package handshake.node;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * ChainDB — persistent storage for the Handshake validator validator.
 * <p>
 * Stores:
 *   headers    height(long)     → raw 236-byte header
 *   blocks     height(long)     → raw block bytes
 *   chainwork  height(long)     → cumulative chainwork (32 bytes)
 *   utxos      "txid:index"     → serialized UtxoEntry
 *   names      nameHash(hex)    → serialized NameEntry
 *   meta       key(String)      → value(String)
 *   peers      ip(String)       → serialized PeerEntry
 * <p>
 * All maps use MVStore for crash-safe, compressed persistence.
 * No wallet data is stored here — the wallet app has its own DB.
 */
public class ChainDB {

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile ChainDB instance;

    public static ChainDB open(String path) {
        if (instance == null) {
            synchronized (ChainDB.class) {
                if (instance == null) instance = new ChainDB(path);
            }
        }
        return instance;
    }

    public static ChainDB get() {
        if (instance == null) throw new IllegalStateException("ChainDB not opened");
        return instance;
    }

    // ── Meta keys ─────────────────────────────────────────────────────────────

    private static final String META_HEADER_TIP    = "header_tip";
    private static final String META_BLOCK_TIP     = "block_tip";
    private static final String META_GENESIS_HASH  = "genesis_hash";
    private static final String META_URKEL_LIVE_ROOT      = "urkel_live_root";
    private static final String META_URKEL_COMMITTED_ROOT = "urkel_committed_root";

    // ── Storage ───────────────────────────────────────────────────────────────

    private final KVStore                  store;
    private final KVMap<Long,   byte[]>    headers;
    private final KVMap<Long,   byte[]>    blocks;
    private final KVMap<Long,   byte[]>    chainwork;
    private final KVMap<String, String>    utxos;
    private final KVMap<String, String>    names;
    private final KVMap<String, String>    meta;
    private final KVMap<String, String>    peers;
    /** Real header hash (hex) -> height. Needed to resolve a peer's
     *  GETHEADERS locator to a height without a linear scan over the
     *  whole chain (which would be up to 32 locator hashes x hundreds
     *  of thousands of headers per request). */
    private final KVMap<String, Long>      hashIndex;
    /** Content-addressed Urkel tree node storage -- see UrkelNodeStore. */
    private final KVMap<String, byte[]>    urkelNodes;

    /** The Urkel name tree, tracking every name's tree-committed state
     *  across blocks -- now persisted to disk (via urkelNodes) after
     *  every block, not just at commit boundaries; see UrkelNameTree's
     *  own class comment for why every-block persistence specifically
     *  is what's needed for correctness across a restart. */
    private final UrkelNameTree nameTree;

    public UrkelNameTree getNameTree() { return nameTree; }

    /** Result of persistNameTreeState()'s two conceptually distinct
     *  phases, split out specifically to answer a real question: when
     *  "persist" dominates per-block timing, is it the per-block
     *  write-new-nodes walk (persistBlockNanos), or the commit/prune-
     *  submission step (maybeCommitNanos) -- which should be near-
     *  instant now that the prune itself runs on its own background
     *  thread, not inline here. */
    public record PersistTiming(long persistBlockNanos, long maybeCommitNanos) {}

    /** Call once per block, after every covenant in that block has
     *  already been applied via getNameTree().applyNameState() --
     *  persists any newly created tree nodes, then advances the
     *  official committed root if this height lands on a real
     *  interval boundary (see UrkelNameTree.maybeCommit()). Both root
     *  pointers get written to meta immediately, not just held in
     *  memory, so a restart at any point resumes from exactly here. */
    public void persistNameTreeState(int height) {
        persistNameTreeStateTimed(height);
    }

    /** Same as persistNameTreeState(), but returns a breakdown of
     *  where the time actually went -- see PersistTiming's own comment
     *  for why this distinction matters. */
    public PersistTiming persistNameTreeStateTimed(int height) {
        long t0 = System.nanoTime();
        nameTree.persistBlock();
        meta.put(META_URKEL_LIVE_ROOT, hex(nameTree.liveRoot()));
        long t1 = System.nanoTime();

        if (nameTree.maybeCommit(height)) {
            meta.put(META_URKEL_COMMITTED_ROOT, hex(nameTree.committedRoot()));
        }
        long t2 = System.nanoTime();

        return new PersistTiming(t1 - t0, t2 - t1);
    }

    private ChainDB(String path) {
        this(path, false);
    }

    /** readOnly=true is for standalone diagnostic tools specifically --
     *  confirmed safe, via a real compile-and-run test against the
     *  actual RocksDB API, to open even while the real, live node is
     *  running and actively writing to the SAME database: RocksDB's
     *  single-writer lock only applies to read-write handles, and its
     *  dedicated read-only mode exists precisely so a separate tool can
     *  inspect a live database's current state without needing the
     *  running node to be stopped first. Deliberately does NOT touch
     *  the instance singleton field at all -- this returns a fresh,
     *  independent object, so a diagnostic tool using this can never
     *  collide with, or accidentally substitute for, the real node's
     *  own ChainDB.open()/get() singleton if it happens to run in the
     *  same process for any reason. */
    public static ChainDB openReadOnly(String path) {
        return new ChainDB(path, true);
    }

    private ChainDB(String path, boolean readOnly) {
        // Switched from MVStoreKVStore to RocksDBKVStore -- see
        // RocksDBKVStore's own class comment, and RocksDBKVMap's
        // runExclusiveOfCompaction() comment specifically, for the
        // full reasoning: MVStore's B-tree/chunk-based design meant a
        // long-running reachability walk could have the exact chunk
        // it was reading physically reorganized out from under it by
        // concurrent compaction, a real, repeatedly observed failure
        // ("Chunk ... not found") that survived three different,
        // progressively more targeted attempts to fix within MVStore's
        // own concurrency model. RocksDB's LSM-tree design and native
        // snapshot isolation eliminate that entire class of problem
        // structurally, confirmed directly via a real compile-and-run
        // test against the actual RocksDB API, not just by reasoning
        // about it. This one line is deliberately the only place that
        // concrete choice is made -- everything else in this class,
        // and every one of its own callers, goes through the
        // KVStore/KVMap interfaces and needed zero other changes.
        this.store = new RocksDBKVStore(path, readOnly);

        this.headers   = store.openLongBytesMap("headers");
        this.blocks    = store.openLongBytesMap("blocks");
        this.chainwork = store.openLongBytesMap("chainwork");
        this.utxos     = store.openStringStringMap("utxos");
        this.names     = store.openStringStringMap("names");
        this.meta      = store.openStringStringMap("meta");
        this.peers     = store.openStringStringMap("peers");
        this.hashIndex = store.openStringLongMap("hashIndex");
        this.urkelNodes = store.openStringBytesMap("urkelNodes");

        UrkelNodeStore nodeStore = new UrkelNodeStore(urkelNodes);
        byte[] persistedLiveRoot = fromHexOrZero(meta.get(META_URKEL_LIVE_ROOT));
        byte[] persistedCommittedRoot = fromHexOrZero(meta.get(META_URKEL_COMMITTED_ROOT));
        this.nameTree = new UrkelNameTree(nodeStore, persistedLiveRoot, persistedCommittedRoot);
    }

    public void close() {
        // FIX: must wait for any in-progress background prune to
        // actually finish BEFORE closing the underlying store --
        // confirmed via a real, caught MVStoreException that a prune
        // still running past this point hits when the file it's
        // reading from gets closed out from under it. See
        // UrkelNameTree.shutdownPruning()'s own comment for the full
        // reasoning.
        if (nameTree != null) {
            nameTree.shutdownPruning();
        }
        store.close();
    }

    // ── Commit ────────────────────────────────────────────────────────────────

    public void commit() {
        store.commit();
    }

    /**
     * Reclaims disk space from old, no-longer-reachable chunks --
     * MVStore's own commit() only makes the current version durable, it
     * doesn't reclaim space from versions that are no longer needed
     * (that's compaction's job specifically). Time-bounded rather than a
     * single unbounded pass, so a periodic call from ChainSync can't
     * stall block/header processing for an unpredictable length of time.
     * The synchronization this used to need against the background
     * prune's own store manipulation now lives inside MVStoreKVStore
     * itself, since both are engine-specific concerns.
     */
    public void compact(int maxMillis) {
        store.compact(maxMillis);
    }

    public String getPath() {
        return store.getFileName();
    }

    public long getDiskSizeBytes() {
        return store.getDiskSizeBytes();
    }

    // ── Header operations ─────────────────────────────────────────────────────

    /**
     * Stores a batch of raw headers starting at startHeight.
     * Caps storage at existingTip + 2016 to prevent fake header inflation.
     */
    public void insertHeaders(List<byte[]> rawHeaders, int startHeight) {
        int existingTip = getHeaderTip();
        if (startHeight > existingTip + 2016) {
            System.out.printf("[ChainDB] Rejecting headers at %d — too far ahead of tip %d%n",
                    startHeight, existingTip);
            return;
        }
        int maxHeight = existingTip + 2016;
        int newTip = startHeight - 1;
        for (int i = 0; i < rawHeaders.size(); i++) {
            long h = startHeight + i;
            if (h > maxHeight) break;
            byte[] header = rawHeaders.get(i);
            if (!headers.containsKey(h)) {
                headers.put(h, header);
            }
            hashIndex.put(hex(HeaderUtil.hash(header)), h);
            newTip = (int) h;
        }
        if (newTip > existingTip) {
            meta.put(META_HEADER_TIP, String.valueOf(newTip));
        }
        store.commit();
    }

    public byte[] getHeader(int height) {
        return headers.get((long) height);
    }

    public int getHeaderTip() {
        String v = meta.get(META_HEADER_TIP);
        return v != null ? Integer.parseInt(v) : -1;
    }

    /** Resolves a real header hash (hex) to its height, or -1 if unknown.
     *  Used to serve GETHEADERS requests without a linear scan. */
    public int getHeightByHash(String hexHash) {
        Long h = hashIndex.get(hexHash);
        return h != null ? h.intValue() : -1;
    }

    /**
     * One-time backfill for the hash index against any headers already
     * stored before this index existed (a real, current situation for
     * this project -- earlier sessions synced hundreds of thousands of
     * headers with no hash index at all). Cheap to check (a single size
     * comparison) and safe to call on every startup; only does real work
     * the one time it's actually needed.
     */
    public void backfillHashIndexIfNeeded() {
        int tip = getHeaderTip();
        if (tip < 0) return;
        if (hashIndex.size() >= tip + 1) return; // already complete
        System.out.println("[ChainDB] Backfilling header hash index (first run after this feature was added)...");
        int done = 0;
        for (int h = 0; h <= tip; h++) {
            byte[] header = headers.get((long) h);
            if (header == null) continue;
            String hashHex = hex(HeaderUtil.hash(header));
            if (!hashIndex.containsKey(hashHex)) {
                hashIndex.put(hashHex, (long) h);
                done++;
            }
        }
        store.commit();
        System.out.println("[ChainDB] Backfill complete: " + done + " entries added.");
    }

    /**
     * Resets header chain to targetHeight, deleting all headers above it.
     * Used to recover from fake header inflation.
     */
    public void resetHeaderTip(int targetHeight) {
        int current = getHeaderTip();
        System.out.printf("[ChainDB] Resetting header tip %d → %d%n", current, targetHeight);
        for (int h = current; h > targetHeight; h--) {
            headers.remove((long) h);
            chainwork.remove((long) h);
        }
        meta.put(META_HEADER_TIP, String.valueOf(targetHeight));
        store.commit();
    }

    /**
     * A genuinely complete wipe of everything derived from chain data --
     * headers, chainwork, blocks, UTXOs, names, and the hash index --
     * plus both the header and block tip metadata. Used when the stored
     * chain data can't be trusted at all (e.g. a genesis-hash mismatch,
     * which can indicate the underlying database file was left in an
     * inconsistent state by an unclean process kill, not just "stale
     * data from before a fix").
     * <p>
     * resetHeaderTip() alone is NOT sufficient for this case: it only
     * clears headers/chainwork, leaving block_tip pointing at whatever
     * height blocks were previously downloaded to. Since blockDownload
     * logic starts from blockTip+1, that stale block_tip would silently
     * skip re-downloading and re-validating every block up to the old
     * tip once headers catch back up to that height -- exactly the
     * heights whose data was potentially corrupted in the first place,
     * now silently trusted forever with no re-validation.
     */
    public void fullReset() {
        System.out.println("[ChainDB] Performing a full reset -- headers, blocks, "
                + "UTXOs, names, and the hash index are all being cleared, not just "
                + "headers, since the stored data as a whole can't be trusted.");
        headers.clear();
        chainwork.clear();
        blocks.clear();
        utxos.clear();
        names.clear();
        hashIndex.clear();
        meta.put(META_HEADER_TIP, "-1");
        meta.put(META_BLOCK_TIP, "-1");
        store.commit();
        // Given this just cleared potentially the entire database's worth
        // of data at once, give compaction a real, larger time budget
        // right away rather than waiting for the next periodic call --
        // this is exactly the moment the most disk space is reclaimable.
        store.compact(30_000);
        System.out.println("[ChainDB] Full reset complete.");
    }

    // ── Block operations ──────────────────────────────────────────────────────

    public void saveBlock(byte[] rawBlock, int height) {
        blocks.put((long) height, rawBlock);
    }

    public byte[] getBlock(int height) {
        return blocks.get((long) height);
    }

    public boolean hasBlock(int height) {
        return blocks.containsKey((long) height);
    }

    /**
     * Returns the highest contiguous block height stored.
     * Recomputes from stored tip downward to find the true boundary.
     */
    public int getBlockTip() {
        String v = meta.get(META_BLOCK_TIP);
        int stored = v != null ? Integer.parseInt(v) : -1;
        // Verify contiguity — walk down from stored tip
        while (stored > 0 && !blocks.containsKey((long) stored)) {
            stored--;
        }
        return stored;
    }

    public void setBlockTip(int height) {
        meta.put(META_BLOCK_TIP, String.valueOf(height));
    }

    // ── Chainwork ─────────────────────────────────────────────────────────────

    public void saveChainwork(int height, BigInteger work) {
        chainwork.put((long) height, work.toByteArray());
    }

    public BigInteger getChainwork(int height) {
        byte[] b = chainwork.get((long) height);
        return b != null ? new BigInteger(1, b) : BigInteger.ZERO;
    }

    // ── UTXO operations ───────────────────────────────────────────────────────

    /**
     * A UTXO entry: value, address version, address hash, covenant type,
     * covenant items (serialized), coinbase flag.
     */
    public record UtxoEntry(
            long value,
            int addrVersion,
            byte[] addrHash,
            int covenantType,
            byte[] covenantData,
            boolean coinbase,
            int height
    ) {
        public String toStorage() {
            return value + "|" + addrVersion + "|"
                    + hex(addrHash) + "|"
                    + covenantType + "|"
                    + hex(covenantData) + "|"
                    + coinbase + "|"
                    + height;
        }

        public static UtxoEntry fromStorage(String s) {
            String[] p = s.split("\\|", 7);
            return new UtxoEntry(
                    Long.parseLong(p[0]),
                    Integer.parseInt(p[1]),
                    fromHex(p[2]),
                    Integer.parseInt(p[3]),
                    fromHex(p[4]),
                    Boolean.parseBoolean(p[5]),
                    p.length > 6 ? Integer.parseInt(p[6]) : 0
            );
        }
    }

    public void saveUtxo(String txid, int index, UtxoEntry entry) {
        utxos.put(txid + ":" + index, entry.toStorage());
    }

    public UtxoEntry getUtxo(String txid, int index) {
        String s = utxos.get(txid + ":" + index);
        return s != null ? UtxoEntry.fromStorage(s) : null;
    }

    public void removeUtxo(String txid, int index) {
        utxos.remove(txid + ":" + index);
    }

    public boolean hasUtxo(String txid, int index) {
        return utxos.containsKey(txid + ":" + index);
    }

    /** Returns all UTXOs at a given address hash (requires address index). */
    public List<String> getUtxoKeysForAddress(byte[] addrHash) {
        String hashHex = hex(addrHash);
        List<String> result = new ArrayList<>();
        for (var e : utxos.entrySet()) {
            UtxoEntry u = UtxoEntry.fromStorage(e.getValue());
            if (hex(u.addrHash()).equals(hashHex)) {
                result.add(e.getKey());
            }
        }
        return result;
    }

    // ── Name state operations ─────────────────────────────────────────────────

    /**
     * Name state entry tracking covenant state for each registered name.
     * <p>
     * Maps nameHash → NameEntry with fields matching hsd's namestate:
     *   name, nameHash, state, height (auction open height),
     *   renewal, owner (txid:index), value, highest, claimed,
     *   renewals, weak, transfer, revoked
     */
    public static class NameEntry {
        public String name;
        public String nameHash;
        public String state;          // OPENING, BIDDING, REVEAL, CLOSED, REVOKED
        public int    height;         // block where auction opened
        public int    renewal;        // last renewal/finalize block
        public String ownerTxid;      // outpoint of current name UTXO
        public int    ownerIndex;
        public long   value;          // locked bid value
        public long   highest;        // highest bid seen
        public int    claimed;        // DNSSEC claim height (0 for auctioned)
        public int    renewals;       // number of renewals
        public boolean weak;
        public int    transfer;       // transfer lockup block (0 if not transferring)
        public int    revoked;
        public boolean registered;    // set explicitly by REGISTER, NOT derived from state -- confirmed via real hsd's getnameproof for "crypto51": a freshly-claimed name has state=CLOSED but registered=false, since CLAIM never sets it (previously this was wrongly derived as state=="CLOSED", which incorrectly marked every claim as registered too)
        public boolean expired = false; // set by maybeExpire() when an auction closes with no revealed bids (or a registration goes unrenewed past renewalWindow) -- confirmed against real hsd's getnameproof, field bit 8
        public byte[] resourceData = new byte[0]; // raw DNS-record blob from the most recent UPDATE/REGISTER covenant, for getnameresource

        public String toStorage() {
            // ownerTxid can genuinely be null now (OPEN no longer sets
            // it, confirmed correct against real hsd's own reset()
            // logic) -- string concatenation would otherwise silently
            // turn a null into the literal text "null", which survives
            // a round trip through storage and later breaks every
            // downstream null-check (including fromHex, which then
            // crashes trying to parse "null" as hex). Write an explicit
            // empty string instead, matching what every null-check here
            // already treats as "no owner".
            String ownerTxidField = (ownerTxid == null) ? "" : ownerTxid;
            return name + "|" + nameHash + "|" + state + "|" + height + "|"
                    + renewal + "|" + ownerTxidField + "|" + ownerIndex + "|"
                    + value + "|" + highest + "|" + claimed + "|"
                    + renewals + "|" + weak + "|" + transfer + "|" + revoked
                    + "|" + hex(resourceData) + "|" + registered + "|" + expired;
        }

        public static NameEntry fromStorage(String s) {
            // Defensive: previously an exception here (e.g. a name record
            // written by an earlier version of this code with a
            // different field layout, now sitting in a database that's
            // survived many code changes across a long testing session)
            // would propagate all the way up and abort processing of the
            // ENTIRE block -- discarding every other transaction's UTXO
            // and name-state updates in that block too, not just this
            // one name's. Treating an unparseable record as "no existing
            // entry" is a far safer fallback than losing everything else
            // in the block over one corrupted/stale record.
            try {
                String[] p = s.split("\\|", 17);
                NameEntry e = new NameEntry();
                e.name       = p[0];
                e.nameHash   = p[1];
                e.state      = p[2];
                e.height     = Integer.parseInt(p[3]);
                e.renewal    = Integer.parseInt(p[4]);
                e.ownerTxid  = p[5];
                e.ownerIndex = Integer.parseInt(p[6]);
                e.value      = Long.parseLong(p[7]);
                e.highest    = Long.parseLong(p[8]);
                e.claimed    = Integer.parseInt(p[9]);
                e.renewals   = Integer.parseInt(p[10]);
                e.weak       = Boolean.parseBoolean(p[11]);
                e.transfer   = Integer.parseInt(p[12]);
                e.revoked    = p.length > 13 ? Integer.parseInt(p[13]) : 0;
                e.resourceData = p.length > 14 && !p[14].isEmpty() ? fromHex(p[14]) : new byte[0];
                // Defaults to false for records written before this field
                // existed -- matches a fresh NameEntry's own default,
                // safer than guessing true for old records.
                e.registered = p.length > 15 && Boolean.parseBoolean(p[15]);
                e.expired    = p.length > 16 && Boolean.parseBoolean(p[16]);
                return e;
            } catch (Exception ex) {
                System.err.println("[ChainDB] WARNING: unparseable NameEntry record, "
                        + "treating as no existing entry: " + ex.getMessage());
                return null;
            }
        }
    }

    public void saveName(NameEntry entry) {
        names.put(entry.nameHash, entry.toStorage());
    }

    public NameEntry getNameByHash(String nameHash) {
        String s = names.get(nameHash);
        return s != null ? NameEntry.fromStorage(s) : null;
    }

    public NameEntry getNameByString(String name) {
        // Linear scan — acceptable since name index is maintained separately
        for (var e : names.entrySet()) {
            NameEntry ne = NameEntry.fromStorage(e.getValue());
            if (name.equalsIgnoreCase(ne.name)) return ne;
        }
        return null;
    }

    public int getNameCount() {
        return names.size();
    }

    /** All names currently tracked, for the "getnames" RPC method.
     *  Skips any record that fails to parse (see NameEntry.fromStorage()'s
     *  defensive handling) rather than letting one bad record break the
     *  whole listing. */
    public List<NameEntry> getAllNames() {
        List<NameEntry> result = new ArrayList<>();
        for (String raw : names.values()) {
            NameEntry e = NameEntry.fromStorage(raw);
            if (e != null) result.add(e);
        }
        return result;
    }

    // ── Peer operations ───────────────────────────────────────────────────────

    public void savePeer(String ip, String data) {
        peers.put(ip, data);
    }

    public String getPeer(String ip) {
        return peers.get(ip);
    }

    public java.util.Map<String, String> getAllPeers() {
        return peers.asUnmodifiableMap();
    }

    // ── Meta operations ───────────────────────────────────────────────────────

    public String getMeta(String key) {
        return meta.get(key);
    }

    public void setMeta(String key, String value) {
        meta.put(key, value);
        store.commit();
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    public int getHeaderCount()  { return headers.size(); }
    public int getBlockCount()   { return blocks.size(); }
    public int getUtxoCount()    { return utxos.size(); }

    /** Sums every UTXO's value -- a real linear scan, acceptable here
     *  since gettxoutsetinfo is an infrequent, user-initiated diagnostic
     *  call, not something on any hot path. */
    public long getTotalUtxoValue() {
        long total = 0;
        for (String raw : utxos.values()) {
            UtxoEntry e = UtxoEntry.fromStorage(raw);
            if (e != null) total += e.value();
        }
        return total;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static String hex(byte[] b) {
        if (b == null || b.length == 0) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] fromHex(String s) {
        if (s == null || s.isEmpty()) return new byte[0];
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    /** Like fromHex, but returns 32 zero bytes for null/empty rather
     *  than a zero-length array -- what a freshly-initialized Urkel
     *  root pointer needs on a genuinely fresh database. */
    private static byte[] fromHexOrZero(String s) {
        if (s == null || s.isEmpty()) return new byte[32];
        return fromHex(s);
    }
}