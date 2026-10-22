package handshake.node.peer;

import handshake.node.storage.ChainDB;
import handshake.node.storage.ConfigDB;
import handshake.node.storage.KVMap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PeerTable — the single source of truth for everything this node knows
 * about any peer: identity (IP, port, Brontide key), provenance (is it a
 * curated seed, something gossiped via ADDR, or a peer that connected to
 * us inbound), and reputation (score, backoff, success/failure history).
 * <p>
 * This replaces three previously separate classes that each held one
 * slice of the same real-world "peer" concept -- SeedDatabase (identity
 * for curated seeds only), PeerScorecard (reputation, keyed by IP with no
 * knowledge of identity), and PeerDiscovery (identity for gossiped/inbound
 * peers only, plus the ADDR wire-format logic). Splitting them had real
 * benefits (seeds protected from a scoring bug by not sharing a deletion
 * path, hot reputation writes separated from a cold curated list, smaller
 * blast radius for a scoring bug) -- but none of those benefits actually
 * require three separate tables, only that certain invariants are
 * enforced. This class enforces the same invariants in one place instead:
 * <p>
 *   - A peer with isSeed=true is NEVER deleted automatically by scoring,
 *     backoff, or any other runtime behavior -- see removePeerPermanently()
 *     for the only way a seed is ever actually removed, which is a
 *     deliberate, explicit, manual action, never an automatic consequence
 *     of bad behavior or unreachability. (Before this class existed, this
 *     was enforced by seeds physically living in a different table that
 *     scoring code had no delete path into at all; here it's enforced by
 *     every delete path explicitly checking isSeed first.)
 *   - All backoffs still reset on startup (stale scores cause connectivity
 *     issues -- unchanged from PeerScorecard's own documented reasoning).
 *   - A keyless (cleartext) peer is still never tracked as connectable --
 *     this project remains Brontide-only throughout.
 * <p>
 * Persistence: one new ConfigDB map ("peers"), replacing the three old
 * ones (ConfigDB's "seeds" and "peerScores" maps, and ChainDB's "peers"
 * map). On first startup after this change, migrateLegacyData() reads all
 * three old maps once and merges them into this one -- nothing already
 * learned (scores, backoff history, discovered addresses) is thrown away.
 * The old maps are left untouched on disk (never deleted), purely so a
 * migration bug can't silently destroy real accumulated history; they're
 * just never written to again once migration has run.
 */
public class PeerTable {

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static final PeerTable INSTANCE = new PeerTable();
    public static PeerTable get() { return INSTANCE; }

    // ── Scoring constants (unchanged from PeerScorecard) ────────────────────────

    private static final int   SCORE_INITIAL             = 50; // known, curated seeds
    private static final int   SCORE_INITIAL_DISCOVERED  = 25; // unverified, gossiped peers -- must earn trust
    private static final int   SCORE_SUCCESS_BONUS       = 5;
    private static final int   SCORE_BRONTIDE_BONUS      = 3;  // extra, on top of SCORE_SUCCESS_BONUS
    private static final int   SCORE_VALID_DATA_BONUS    = 2;
    private static final int   SCORE_INVALID_DATA_PENALTY = 30; // heavier than a plain connection failure
    private static final int   SCORE_FAILURE_PENALTY     = 15;
    private static final int   SCORE_STALE_TIP_PENALTY   = 3;
    private static final int   SCORE_IMPLAUSIBLE_TIP_PENALTY = 5;
    private static final int   SCORE_MAX                 = 100;
    private static final int   SCORE_BACKOFF_THRESHOLD   = 25;
    private static final int   SCORE_BLACKLIST           = 0;

    /** Default hsd cleartext P2P port. Cleartext peers are only ever auto-dialed
     *  on this port (a gossiped host:port is untrusted input -- never let it make
     *  us connect to an arbitrary port). */
    public static final int PLAIN_PORT = 12038;
    /** Cleartext (keyless) peers lose exactly 25 points against a Brontide peer: the only thing wrong with
     *  them is that they do not encrypt, so a cleartext peer that is otherwise perfect can reach 75 (SCORE_MAX - 25)
     *  but never the full 100. Cleartext candidates are still dialed after Brontide ones. */
    private static final int   SCORE_PLAIN_CAP           = 75;

    private static final double LATENCY_EMA_ALPHA        = 0.3;
    private static final double SCORE_FAST_THRESHOLD_MS  = 800;
    private static final double SCORE_SLOW_THRESHOLD_MS  = 5000;
    private static final int    SCORE_LATENCY_ADJUST     = 1;

    // ── Gossip address hygiene ────────────────────────────────────────────────
    /** Ignore an ADDR entry whose own 'last seen' timestamp is older than this. */
    static final long ADDR_MAX_AGE_MS     = 30L * 24 * 3600_000L;   // hsd HostList.HORIZON_DAYS = 30
    /** Forget a gossip-learned address nobody has re-announced for this long. */
    static final long ADDR_EXPIRE_MS      = 30L * 24 * 3600_000L;
    /** Forget a gossip-learned address after this many failed dials with no success ever. */
    static final int  ADDR_MAX_FAILURES   = 5;
    /** Tolerated clock skew for a timestamp in the future (clamped to now beyond it). */
    static final long ADDR_FUTURE_SLACK_MS = 10 * 60_000L;

    private static final long[] BACKOFF_MS = {
            5  * 60_000L,   // 0: 5 minutes
            30 * 60_000L,   // 1: 30 minutes  <- seed cap
            2  * 3600_000L, // 2: 2 hours
            24 * 3600_000L  // 3: 24 hours    <- non-seed max
    };
    private static final int SEED_MAX_BACKOFF_LEVEL = 1;

    // ── Peer record ───────────────────────────────────────────────────────────

    /**
     * One row per peer, keyed by IP. Mutable, in-memory-live fields
     * (mirrors PeerScorecard.PeerRecord's existing convention of public
     * mutable fields rather than a record, since this is updated in place
     * far more than it's replaced).
     */
    public static class Peer {
        public final String ip;
        public int     port = 44806;
        public String  brontideKey = "";   // base32-encoded compressed pubkey, "" if unknown
        public boolean isSeed;             // NEVER auto-deleted if true -- see class comment
        public String  label = "";         // human-readable, e.g. seeds.txt's label
        public String  source = "";        // "seed" | "addr:<ip>" | "inbound:<ip>" | "rpc-addnode" | ...
        public long    discoveredAt;

        // Reputation (same fields/semantics as the old PeerScorecard.PeerRecord)
        public int     score;
        public int     backoffLevel;
        public long    backoffUntil;
        public int     successCount;
        public int     failureCount;
        public long    lastSuccessTime;
        public long    lastFailureTime;
        public long    lastAttemptTime;
        public String  lastAgent = "";
        public int     lastHeight;
        public String  extra1 = "0";       // unknown real-format field, preserved verbatim from the recovered data
        public String  extra3 = "0";       // ditto
        public boolean usesBrontide;       // in-memory only
        public int     validDataCount;     // in-memory only
        public int     invalidDataCount;   // in-memory only
        public double  avgLatencyMs = -1;  // in-memory only; -1 = no data yet
        public boolean banned;             // in-memory only; expires after BAN_DURATION_MS (hsd: 24 h), see PeerTable.expireBan
        public String  banReason;          // in-memory only
        public long    banTime;            // in-memory only
        public final java.util.ArrayDeque<String> penalties = new java.util.ArrayDeque<>(); // in-memory: last few score-lowering events
        public long    gossipTime;         // ms: newest 'last seen' timestamp any peer announced for this address (0 = unknown)
        public long    lastRecoveryTime;   // in-memory only; when applyDecay last gave this peer another chance
        public String  lastFailureReason = ""; // why the most recent connection attempt failed (short, no '|')

        Peer(String ip) { this.ip = ip; }

        public boolean hasBrontideKey() { return brontideKey != null && !brontideKey.isBlank(); }

        public boolean isBackedOff() { return System.currentTimeMillis() < backoffUntil; }

        public boolean isBlacklisted() {
            return score <= SCORE_BLACKLIST
                    && backoffLevel >= BACKOFF_MS.length - 1
                    && isBackedOff();
        }

        public String status() {
            if (isBlacklisted()) return "BLACKLISTED";
            if (isBackedOff())   return "BACKOFF(" + formatDuration(backoffUntil - System.currentTimeMillis()) + ")";
            if (score >= 70)     return "HEALTHY";
            if (score >= 40)     return "DEGRADED";
            return "POOR";
        }

        /** Pipe-delimited storage format (new, not shared with the old
         *  recovered comma-delimited PeerScorecard format or the old
         *  SeedDatabase/PeerDiscovery pipe formats -- this is a fresh,
         *  single format for the unified table). */
        String toStorage() {
            return port + "|" + nz(brontideKey) + "|" + isSeed + "|" + nz(label) + "|" + nz(source) + "|"
                    + discoveredAt + "|" + score + "|" + extra1 + "|" + failureCount + "|" + extra3 + "|"
                    + successCount + "|" + backoffLevel + "|" + lastAttemptTime + "|" + lastSuccessTime + "|"
                    + lastFailureTime + "|" + lastHeight + "|" + nz(lastAgent) + "|" + backoffUntil + "|" + gossipTime
                    + "|" + nz(lastFailureReason).replace('|', '/').replace('\n', ' ');
        }

        static Peer fromStorage(String ip, String s) {
            Peer p = new Peer(ip);
            String[] f = s.split("\\|", -1);
            p.port            = parseIntSafe(f, 0, 44806);
            p.brontideKey     = f.length > 1 ? f[1] : "";
            p.isSeed          = f.length > 2 && Boolean.parseBoolean(f[2]);
            p.label           = f.length > 3 ? f[3] : "";
            p.source          = f.length > 4 ? f[4] : "";
            p.discoveredAt    = parseLongSafe(f, 5, 0);
            p.score           = parseIntSafe(f, 6, p.isSeed ? SCORE_INITIAL : SCORE_INITIAL_DISCOVERED);
            p.extra1          = f.length > 7 ? f[7] : "0";
            p.failureCount    = parseIntSafe(f, 8, 0);
            p.extra3          = f.length > 9 ? f[9] : "0";
            p.successCount    = parseIntSafe(f, 10, 0);
            p.backoffLevel    = parseIntSafe(f, 11, 0);
            p.lastAttemptTime = parseLongSafe(f, 12, 0);
            p.lastSuccessTime = parseLongSafe(f, 13, 0);
            p.lastFailureTime = parseLongSafe(f, 14, 0);
            p.lastHeight      = parseIntSafe(f, 15, 0);
            p.lastAgent       = f.length > 16 ? f[16] : "";
            p.backoffUntil    = parseLongSafe(f, 17, 0);
            p.gossipTime      = parseLongSafe(f, 18, 0);
            p.lastFailureReason = f.length > 19 ? f[19] : "";
            return p;
        }

        private static String nz(String s) { return s != null ? s : ""; }

        @Override
        public String toString() {
            return (label.isBlank() ? ip : label + " (" + ip + ")") + ":" + port;
        }
    }

    /**
     * A peer we can attempt to connect to. brontideKey is either a real
     * 33-byte key (dial over Brontide) or null (a cleartext peer on
     * {@link #PLAIN_PORT} -- see {@link #plain()}).
     */
    public record ConnectTarget(String ip, int port, byte[] brontideKey, String label) {
        public boolean plain() { return brontideKey == null; }
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final ConcurrentHashMap<String, Peer> peers = new ConcurrentHashMap<>();

    /** Our own confirmed public IP, if known -- never stored, listed or dialed
     *  as a peer (our own self-announce comes back to us through gossip). */
    private volatile String selfIp = null;
    public void setSelfIp(String ip) {
        this.selfIp = ip;
        if (ip != null) forgetSelf();
    }

    /** Our own Brontide public key (base32). A peer row carrying this key is this node itself, whatever its IP. */
    private volatile String selfKey = null;
    public void setSelfKey(String base32Key) {
        this.selfKey = (base32Key == null || base32Key.isBlank()) ? null : base32Key;
        if (this.selfKey != null && peersMap != null) forgetSelf();
    }

    private boolean isSelf(String ip, String key) {
        if (ip != null && ip.equals(selfIp)) return true;
        return selfKey != null && key != null && key.equals(selfKey);
    }

    /** Removes any stored row that is this node itself (by confirmed IP or by our own key). */
    private void forgetSelf() {
        boolean removed = false;
        for (Peer r : new ArrayList<>(peers.values())) {
            if (!isSelf(r.ip, r.brontideKey) || pinned.contains(r.ip)) continue;
            peers.remove(r.ip);
            if (peersMap != null) peersMap.remove(r.ip);
            System.out.printf("[PeerTable] Removed %s from the peer table: it is this node itself.%n", r.ip);
            removed = true;
        }
        if (removed && peersMap != null) ConfigDB.get().commit();
    }
    private KVMap<String, String> peersMap;

    // ── Pinned peers ──────────────────────────────────────────────────────────
    //
    // A pinned peer is one the operator explicitly wants a standing connection
    // to (typically their own other node). Pinned peers are dialed before
    // everything else, don't count against max.outbound, are never put in
    // backoff, and their score is floored so ordinary penalties can't lock
    // them out. Stored comma-separated under "peers.pinned" in the settings
    // map. Managed with RPC: addnode "[key@]ip[:port]" add | remove.

    private static final String PINNED_SETTING = "peers.pinned";
    private static final int    SCORE_PINNED_FLOOR = 50;
    private final Set<String> pinned = ConcurrentHashMap.newKeySet();
    private KVMap<String, String> settingsMap;

    public boolean isPinned(String ip) { return ip != null && pinned.contains(ip); }

    public Set<String> getPinned() { return new TreeSet<>(pinned); }

    /** Pins a peer (creating a row if needed) and clears any backoff / low score. */
    public void pin(String ip) {
        if (ip == null || ip.isBlank()) return;
        pinned.add(ip);
        Peer r = getOrCreate(ip);
        r.banned = false;
        lift(r);
        persist(r);
        savePinned();
        System.out.printf("[PeerTable] Pinned peer %s (score %d).%n", ip, r.score);
    }

    public void unpin(String ip) {
        if (pinned.remove(ip)) {
            savePinned();
            System.out.printf("[PeerTable] Unpinned peer %s.%n", ip);
        }
    }

    private void savePinned() {
        if (settingsMap == null) return;
        settingsMap.put(PINNED_SETTING, String.join(",", new TreeSet<>(pinned)));
        ConfigDB.get().commit();
    }

    /** Remove backoff and raise the score to the pinned floor. */
    private void lift(Peer r) {
        r.backoffUntil = 0;
        r.backoffLevel = 0;
        r.score = Math.max(r.score, SCORE_PINNED_FLOOR);
    }

    private PeerTable() {}

    // ── Initialization ────────────────────────────────────────────────────────

    /**
     * Wires the table to persistent storage, migrates legacy data the
     * first time this runs against an existing install, merges seeds.txt,
     * and resets all backoffs (unchanged from PeerScorecard's own startup
     * behavior -- stale backoff state across restarts caused real
     * connectivity issues before).
     */
    public void init(ConfigDB configDb, ChainDB chainDb) {
        this.peersMap = configDb.peersMap();
        int loaded = 0;
        for (var e : peersMap.entrySet()) {
            String key = e.getKey();
            if (key.startsWith("deleted:") || key.startsWith("forgotten:")) continue; // tombstones, not peer rows
            peers.put(key, Peer.fromStorage(key, e.getValue()));
            loaded++;
        }
        if (loaded == 0) {
            migrateLegacyData(configDb, chainDb);
        }
        mergeFromResourceFile();
        resetAllBackoffs();
        this.settingsMap = configDb.settingsMap();
        String pinnedCsv = settingsMap.get(PINNED_SETTING);
        if (pinnedCsv != null) {
            for (String ip : pinnedCsv.split(",")) {
                ip = ip.trim();
                if (ip.isEmpty()) continue;
                pinned.add(ip);
                Peer r = peers.get(ip);
                if (r != null) { lift(r); persist(r); }
            }
            if (!pinned.isEmpty()) System.out.println("[PeerTable] Pinned peers: " + new TreeSet<>(pinned));
        }
        applyRetiredSeeds();   // after the pinned set is loaded, before the prune below
        pruneGossip(true);   // after the pinned set is loaded, so a pinned peer is never pruned
        dropNonPublicRows();
        forgetSelf();
        System.out.printf("[PeerTable] Loaded %d peers (%d seeds) from the config database.%n",
                peers.size(), (int) peers.values().stream().filter(p -> p.isSeed).count());
    }

    /**
     * One-time migration from the three old storage locations this
     * project used before this class existed. Only runs when the new
     * "peers" map is completely empty, so it can never overwrite anything
     * this class has already written. Old maps are left on disk exactly
     * as they were -- this only reads them, never deletes or clears them.
     */
    private void migrateLegacyData(ConfigDB configDb, ChainDB chainDb) {
        KVMap<String, String> oldSeeds = configDb.seedsMap();
        KVMap<String, String> oldScores = configDb.peerScoresMap();
        Map<String, String> oldDiscovered = chainDb.getAllPeers();

        if (oldSeeds.size() == 0 && oldScores.size() == 0 && oldDiscovered.isEmpty()) {
            return; // genuinely fresh install, nothing to migrate
        }

        int seedCount = 0, scoreCount = 0, discoveredCount = 0, tombstoneCount = 0;

        for (var e : oldSeeds.entrySet()) {
            String key = e.getKey();
            if (key.startsWith("deleted:")) {
                peersMap.put(key, "true"); // carry the tombstone forward verbatim
                tombstoneCount++;
                continue;
            }
            String ip = key;
            String[] p = e.getValue().split("\\|", -1);
            Peer peer = peers.computeIfAbsent(ip, Peer::new);
            peer.brontideKey = p.length > 0 ? p[0] : "";
            peer.port        = p.length > 1 ? parseIntSafe(p, 1, 44806) : 44806;
            peer.label       = p.length > 2 ? p[2] : "seed";
            peer.isSeed      = true;
            peer.source      = "seed";
            seedCount++;
        }

        for (var e : oldScores.entrySet()) {
            String ip = e.getKey();
            Peer peer = peers.computeIfAbsent(ip, Peer::new);
            // Old PeerScorecard format: score,extra1,failureCount,extra3,
            // successCount,backoffLevel,lastAttempt,lastSuccess,lastFailure,
            // height,agent[,backoffUntil]
            String[] f = e.getValue().split(",", -1);
            peer.score           = parseIntSafe(f, 0, peer.isSeed ? SCORE_INITIAL : SCORE_INITIAL_DISCOVERED);
            peer.extra1          = f.length > 1 ? f[1] : "0";
            peer.failureCount    = parseIntSafe(f, 2, 0);
            peer.extra3          = f.length > 3 ? f[3] : "0";
            peer.successCount    = parseIntSafe(f, 4, 0);
            peer.backoffLevel    = parseIntSafe(f, 5, 0);
            peer.lastAttemptTime = parseLongSafe(f, 6, 0);
            peer.lastSuccessTime = parseLongSafe(f, 7, 0);
            peer.lastFailureTime = parseLongSafe(f, 8, 0);
            peer.lastHeight      = parseIntSafe(f, 9, 0);
            peer.lastAgent       = f.length > 10 ? f[10] : "";
            peer.backoffUntil    = parseLongSafe(f, 11, 0);
            scoreCount++;
        }

        for (var e : oldDiscovered.entrySet()) {
            String ip = e.getKey();
            if (peers.containsKey(ip)) continue; // already a seed or scored peer -- don't downgrade it
            String[] p = e.getValue().split("\\|", -1);
            Peer peer = peers.computeIfAbsent(ip, Peer::new);
            peer.brontideKey  = p.length > 0 ? p[0] : "";
            peer.port         = p.length > 1 ? parseIntSafe(p, 1, 44806) : 44806;
            peer.discoveredAt = p.length > 2 ? parseLongSafe(p, 2, System.currentTimeMillis()) : System.currentTimeMillis();
            peer.source       = p.length > 3 ? p[3] : "unknown";
            peer.score        = SCORE_INITIAL_DISCOVERED;
            discoveredCount++;
        }

        for (Peer p : peers.values()) {
            peersMap.put(p.ip, p.toStorage());
        }
        ConfigDB.get().commit();
        System.out.printf("[PeerTable] Migrated legacy data: %d seeds, %d scored peers, %d discovered "
                        + "peers, %d tombstone(s) -- nothing discarded, old data left on disk untouched.%n",
                seedCount, scoreCount, discoveredCount, tombstoneCount);
    }

    /** Same seeds.txt merge behavior SeedDatabase used to provide --
     *  additive only, never overrides what's already known about an IP,
     *  never resurrects a tombstoned one. Promotes an already-known
     *  non-seed peer to isSeed=true if it now appears in seeds.txt,
     *  without touching its accumulated score/history. */
    private void mergeFromResourceFile() {
        List<SeedLine> fromFile = loadSeedsFromResource();
        int added = 0, promoted = 0, alreadyKnown = 0, tombstoned = 0;
        for (SeedLine line : fromFile) {
            if (isDeleted(line.ip)) { tombstoned++; continue; }
            if (isSelf(line.ip, line.brontideKey) || isNonPublic(line.ip)) {
                System.out.printf("[PeerTable] seeds.txt: skipping %s (%s)%n", line.ip,
                        isSelf(line.ip, line.brontideKey) ? "this node itself" : "not a public address");
                tombstoned++;
                continue;
            }
            Peer existing = peers.get(line.ip);
            if (existing == null) {
                Peer peer = new Peer(line.ip);
                peer.brontideKey = line.brontideKey;
                peer.port        = line.port;
                peer.label       = line.label;
                peer.isSeed      = true;
                peer.source      = "seed";
                peer.score       = SCORE_INITIAL;
                peers.put(line.ip, peer);
                peersMap.put(line.ip, peer.toStorage());
                added++;
            } else if (!existing.isSeed) {
                existing.isSeed = true;
                existing.label  = line.label;
                if (!existing.hasBrontideKey()) existing.brontideKey = line.brontideKey;
                peersMap.put(line.ip, existing.toStorage());
                promoted++;
            } else {
                alreadyKnown++;
            }
        }
        if (added > 0 || promoted > 0) ConfigDB.get().commit();
        System.out.printf("[PeerTable] seeds.txt: %d merged in, %d promoted, %d already known, "
                + "%d tombstoned/skipped.%n", added, promoted, alreadyKnown, tombstoned);
    }

    /** Deletes stored rows whose address is loopback, private, link-local, CGNAT or multicast. Gossip can never
     *  create them, so they are leftovers (tests, old versions). A peer the operator pinned is kept: pinning a LAN
     *  machine is a deliberate choice. */
    private void dropNonPublicRows() {
        int dropped = 0;
        for (Peer r : new ArrayList<>(peers.values())) {
            if (!isNonPublic(r.ip) || pinned.contains(r.ip)) continue;
            peers.remove(r.ip);
            if (peersMap != null) peersMap.remove(r.ip);
            dropped++;
        }
        if (dropped > 0) {
            ConfigDB.get().commit();
            System.out.printf("[PeerTable] Dropped %d stored peer(s) with a loopback or private address.%n", dropped);
        }
    }

    private record SeedLine(String brontideKey, String ip, int port, String label) {}

    /** ip -> reason, from the "retired|ip|reason" lines of seeds.txt (filled while the file is read). */
    private static final Map<String, String> RETIRED_SEEDS = new java.util.LinkedHashMap<>();

    /**
     * Seeds are merged additively, so removing a line from seeds.txt never removed the seed from a node that already
     * stored it: dead seeds kept coming back as "available". A "retired|ip|reason" line in seeds.txt fixes that. At
     * startup each stored seed row for a retired address is demoted: a seed that never connected successfully is
     * forgotten (removed, and not re-added from gossip for a week); one that has worked before stays as an ordinary
     * peer (no longer a seed, score capped at the retry floor) and earns its way back or is pruned. A pinned peer is
     * never touched. Runs after the pinned set is loaded.
     */
    private void applyRetiredSeeds() {
        if (RETIRED_SEEDS.isEmpty() || peersMap == null) return;
        int forgotten = 0, demoted = 0;
        for (Map.Entry<String, String> e : RETIRED_SEEDS.entrySet()) {
            Peer r = peers.get(e.getKey());
            if (r == null || !r.isSeed || pinned.contains(r.ip)) continue;
            if (r.successCount == 0) {
                forget(r.ip);
                forgotten++;
                System.out.printf("[PeerTable] Retired seed %s (%s): never connected, removed.%n", r.ip, e.getValue());
            } else {
                r.isSeed = false;
                r.score = Math.min(r.score, SCORE_BACKOFF_THRESHOLD);
                peersMap.put(r.ip, r.toStorage());
                demoted++;
                System.out.printf("[PeerTable] Retired seed %s (%s): kept as an ordinary peer, no longer a seed.%n", r.ip, e.getValue());
            }
        }
        if (forgotten > 0 || demoted > 0) ConfigDB.get().commit();
    }

    private static List<SeedLine> loadSeedsFromResource() {
        List<SeedLine> loaded = new ArrayList<>();
        try (InputStream in = PeerTable.class.getResourceAsStream("/seeds.txt")) {
            if (in == null) {
                throw new IllegalStateException(
                        "seeds.txt is missing from the classpath -- this project has no other "
                                + "way to find its first peer on a fresh install.");
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                int lineNum = 0;
                while ((line = reader.readLine()) != null) {
                    lineNum++;
                    String trimmed = line.trim();
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                    String[] p = trimmed.split("\\|", -1);
                    if (p[0].trim().equalsIgnoreCase("retired")) {
                        // retired|ip|reason : an address that must no longer be a seed (see applyRetiredSeeds)
                        if (p.length >= 2 && !p[1].trim().isEmpty()) {
                            RETIRED_SEEDS.put(p[1].trim(), p.length >= 3 ? p[2].trim() : "");
                        } else {
                            System.err.printf("[PeerTable] seeds.txt line %d: retired entry needs an ip -- skipping: %s%n", lineNum, line);
                        }
                        continue;
                    }
                    if (p.length < 4) {
                        System.err.printf("[PeerTable] seeds.txt line %d malformed -- skipping: %s%n", lineNum, line);
                        continue;
                    }
                    String brontideKey = p[0].trim();
                    String ip = p[1].trim();
                    int port = parseIntSafe(p[2].trim());
                    String label = p[3].trim();
                    if (brontideKey.isEmpty() || ip.isEmpty()) {
                        System.err.printf("[PeerTable] seeds.txt line %d missing brontideKey or ip -- "
                                + "skipping: %s%n", lineNum, line);
                        continue;
                    }
                    loaded.add(new SeedLine(brontideKey, ip, port, label));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load seeds.txt", e);
        }
        return loaded;
    }

    private static int parseIntSafe(String s) {
        try { return Integer.parseInt(s); } catch (Exception e) { return 44806; }
    }

    /** How long an address that was dropped for failing 5 dials stays forgotten. Without this the same dead address
     *  is announced again by other nodes within minutes, re-added as "new", and the cycle never ends. */
    private static final long FORGET_MS = 7L * 24 * 3600_000L;

    private boolean isForgotten(String ip) {
        if (peersMap == null) return false;
        String v = peersMap.get("forgotten:" + ip);
        if (v == null) return false;
        try {
            if (Long.parseLong(v) > System.currentTimeMillis()) return true;
        } catch (NumberFormatException ignored) { /* treat as expired */ }
        peersMap.remove("forgotten:" + ip);
        return false;
    }

    private void forget(String ip) {
        peers.remove(ip);
        if (peersMap != null) {
            peersMap.remove(ip);
            peersMap.put("forgotten:" + ip, Long.toString(System.currentTimeMillis() + FORGET_MS));
        }
    }

    private boolean isDeleted(String ip) {
        return "true".equalsIgnoreCase(peersMap.get("deleted:" + ip));
    }

    // ── Identity queries ──────────────────────────────────────────────────────

    public boolean isSeed(String ip) {
        Peer p = peers.get(ip);
        return p != null && p.isSeed;
    }

    public boolean isDiscovered(String ip) {
        return peers.containsKey(ip);
    }

    public Peer getSeed(String ip) {
        Peer p = peers.get(ip);
        return (p != null && p.isSeed) ? p : null;
    }

    public List<Peer> getBrontideSeeds() {
        return peers.values().stream().filter(p -> p.isSeed && p.hasBrontideKey()).toList();
    }

    public String getBrontideKeyByIp(String ip) {
        Peer p = peers.get(ip);
        return (p != null && p.hasBrontideKey()) ? p.brontideKey : null;
    }

    /** Upper bound on keyless ("plain", not-yet-connectable) peers we remember
     *  from gossip, so the table can't grow without limit. Keyed peers are
     *  never capped -- they are the ones we can actually connect to. */
    private static final int MAX_KNOWN_PEERS = 500;

    /** Adds a peer learned from ADDR gossip, an inbound connection, or RPC
     *  addnode. An already-known peer is left alone -- EXCEPT that a peer we
     *  only know as keyless ("plain") is upgraded in place when a real
     *  Brontide key for it finally turns up (a later ADDR entry, an inbound
     *  Brontide connection, or RPC addnode), so learning a key is never
     *  silently ignored just because the IP was already on file. */
    public void addDiscovered(String brontideKey, String ip, int port, String source) {
        if (addDiscoveredNoCommit(brontideKey, ip, port, source)) {
            ConfigDB.get().commit();
        }
    }

    /** @return true if the table changed (caller is responsible for commit). */
    private boolean addDiscoveredNoCommit(String brontideKey, String ip, int port, String source) {
        return addDiscoveredNoCommit(brontideKey, ip, port, source, System.currentTimeMillis());
    }

    private boolean addDiscoveredNoCommit(String brontideKey, String ip, int port, String source, long seenMs) {
        if (ip == null || ip.isBlank()) return false;
        if (isDeleted(ip)) return false;
        if (isForgotten(ip)) return false;
        if (ip.equals(selfIp)) return false;
        if (selfKey != null && selfKey.equals(brontideKey)) return false;   // our own self-announce coming back
        String key = brontideKey != null ? brontideKey : "";
        Peer existing = peers.get(ip);
        if (existing != null) {
            if (seenMs > existing.gossipTime) {
                existing.gossipTime = seenMs;
                peersMap.put(ip, existing.toStorage());   // committed with the next commit
            }
            if (!existing.hasBrontideKey() && !key.isBlank()) {
                existing.brontideKey = key;
                existing.port = port;
                peersMap.put(ip, existing.toStorage());
                System.out.printf("[PeerTable] Learned Brontide key for already-known peer %s (%s) "
                        + "-- now connectable.%n", ip, source);
                return true;
            }
            return false; // already known, seed or otherwise
        }
        if (key.isBlank() && peers.size() >= MAX_KNOWN_PEERS) return false;
        Peer peer = new Peer(ip);
        peer.brontideKey  = key;
        peer.port         = port;
        peer.source       = source;
        peer.discoveredAt = System.currentTimeMillis();
        peer.gossipTime   = seenMs;
        peer.score        = SCORE_INITIAL_DISCOVERED;
        peers.put(ip, peer);
        peersMap.put(ip, peer.toStorage());
        // Keyed peers are rare and worth a line each; keyless gossip arrives
        // dozens at a time and is summarised by onAddrMessage() instead.
        if (!key.isBlank()) {
            System.out.printf("[PeerTable] Discovered peer: %s (%s)%n", ip, source);
        }
        return true;
    }

    /**
     * The ONLY way a peer -- seed or otherwise -- is ever permanently
     * removed. Deliberately manual: never called automatically by
     * scoring, backoff, or any failure path. Writes a tombstone so
     * seeds.txt (or a future ADDR message) never silently resurrects it.
     */
    public void removePeerPermanently(String ip, String reason) {
        peers.remove(ip);
        peersMap.remove(ip);
        peersMap.put("deleted:" + ip, "true");
        ConfigDB.get().commit();
        System.out.printf("[PeerTable] Permanently removed %s: %s%n", ip, reason);
    }

    // ── ADDR wire format handling (moved from PeerDiscovery) ────────────────────

    /**
     * Processes an ADDR message received from a peer. Brontide-only: an
     * entry is only ever added if it carries a real (non-zero) key AND is
     * on port 44806. Unchanged from PeerDiscovery's own behavior/comments.
     */
    public void onAddrMessage(byte[] msg, String fromIp) {
        if (msg.length == 0) {
            System.out.printf("[PeerTable] Received empty ADDR from %s (0 bytes).%n", fromIp);
            return;
        }
        // The entry count is a variable-length integer (hsd writeVarint): one byte up to 252, otherwise a marker
        // byte (0xFD / 0xFE) followed by 2 or 4 bytes, little-endian. hsd sends up to 1000 entries per message.
        int pos;
        long declared;
        int first = msg[0] & 0xFF;
        if (first < 0xFD) {
            declared = first; pos = 1;
        } else if (first == 0xFD && msg.length >= 3) {
            declared = (msg[1] & 0xFF) | ((msg[2] & 0xFF) << 8); pos = 3;
        } else if (first == 0xFE && msg.length >= 5) {
            declared = (msg[1] & 0xFFL) | ((msg[2] & 0xFFL) << 8) | ((msg[3] & 0xFFL) << 16) | ((msg[4] & 0xFFL) << 24); pos = 5;
        } else {
            System.out.printf("[PeerTable] ADDR from %s: unreadable entry count (first byte 0x%02x, %d byte payload).%n",
                    fromIp, first, msg.length);
            return;
        }
        final int MAX_ADDR_ENTRIES = 1000;
        int entryCount = (int) Math.min(declared, MAX_ADDR_ENTRIES);

        int newBrontide = 0, knownBrontide = 0, newPlain = 0, knownPlain = 0;
        int stale = 0, brontideOtherPort = 0, plainOtherPort = 0, badAddress = 0, nonIpv4 = 0;
        boolean tableChanged = false;
        long nowMs = System.currentTimeMillis();
        int parsed = 0;
        try {
            for (int i = 0; i < entryCount && pos + 88 <= msg.length; i++, parsed++) {
                int e = pos;
                pos += 88;                                   // every entry is exactly 88 bytes
                long tsSec = 0;
                for (int b = 7; b >= 0; b--) tsSec = (tsSec << 8) | (msg[e + b] & 0xFF);
                long seenMs = (tsSec < 0 || tsSec > 100_000_000_000L) ? 0 : tsSec * 1000L;
                if (seenMs > nowMs + ADDR_FUTURE_SLACK_MS) seenMs = nowMs;   // bad clock: treat as just seen
                // e+16: address type, e+17..e+32: 16-byte address, e+33..e+52: reserved, e+53: port, e+55: key
                boolean mappedIpv4 = true;
                for (int b = 0; b < 10; b++) if (msg[e + 17 + b] != 0) { mappedIpv4 = false; break; }
                if (!mappedIpv4) { nonIpv4++; continue; }    // IPv6 / onion: this node only dials IPv4
                String ip = (msg[e + 29] & 0xFF) + "." + (msg[e + 30] & 0xFF)
                        + "." + (msg[e + 31] & 0xFF) + "." + (msg[e + 32] & 0xFF);
                if (!isValidIp(ip)) { badAddress++; continue; }
                if (seenMs == 0 || nowMs - seenMs > ADDR_MAX_AGE_MS) { stale++; continue; }
                int port = (msg[e + 53] & 0xFF) | ((msg[e + 54] & 0xFF) << 8);
                byte[] keyBytes = Arrays.copyOfRange(msg, e + 55, e + 88);

                if (isAllZero(keyBytes)) {
                    // Plain (cleartext) peer. Only the standard cleartext port is ever dialed, so an entry on any
                    // other port (often an inbound peer's random source port) could never become a real peer.
                    if (port != PLAIN_PORT) { plainOtherPort++; continue; }
                    if (addDiscoveredNoCommit("", ip, port, "addr:" + fromIp, seenMs)) { newPlain++; tableChanged = true; }
                    else knownPlain++;
                    continue;
                }
                if (port != 44806) { brontideOtherPort++; continue; }
                String base32Key = NodeIdentity.base32Encode(keyBytes);
                if (addDiscoveredNoCommit(base32Key, ip, port, "addr:" + fromIp, seenMs)) { newBrontide++; tableChanged = true; }
                else knownBrontide++;
            }
            if (tableChanged) ConfigDB.get().commit();
            System.out.printf("[PeerTable] ADDR from %s: %d entries%s -- usable: %d Brontide (%d new), %d cleartext (%d new); "
                            + "ignored: %d stale, %d Brontide on another port, %d cleartext on another port, "
                            + "%d invalid address, %d non-IPv4.%n",
                    fromIp, parsed, declared != parsed ? " of " + declared + " declared" : "",
                    newBrontide + knownBrontide, newBrontide, newPlain + knownPlain, newPlain,
                    stale, brontideOtherPort, plainOtherPort, badAddress, nonIpv4);
        } catch (Exception e) {
            System.out.printf("[PeerTable] ADDR from %s: failed to parse "
                            + "(%d declared entries, %d byte payload): %s%n",
                    fromIp, declared, msg.length, e);
        }
    }

    /** A peer we may tell others about: a verified, recently working, dialable address. */
    public record AnnouncePeer(String ip, int port, byte[] key, long timeSec) { }

    /**
     * Addresses to share when a peer asks for ours (GETADDR): only peers that have really worked within
     * {@code maxAgeMs}, are not banned or backed off, and sit on a standard dialable port -- never unverified gossip.
     * The "last seen" time is the peer's real last success, so receivers can judge freshness. Shuffled, capped.
     */
    public List<AnnouncePeer> announceablePeers(long maxAgeMs, int limit) {
        long now = System.currentTimeMillis();
        List<AnnouncePeer> out = new ArrayList<>();
        for (Peer p : peers.values()) {
            if (p.successCount <= 0 || p.banned || p.isBackedOff() || isSelf(p.ip, p.brontideKey)) continue;
            if (now - p.lastSuccessTime > maxAgeMs) continue;
            if (!isValidIp(p.ip)) continue;               // IPv4 public addresses only
            byte[] kb = null;
            if (p.hasBrontideKey()) {
                if (p.port != 44806) continue;
                kb = NodeIdentity.base32Decode(p.brontideKey);
                if (kb == null || kb.length != 33) continue;
            } else if (p.port != PLAIN_PORT) {
                continue;
            }
            out.add(new AnnouncePeer(p.ip, p.port, kb, p.lastSuccessTime / 1000));
        }
        Collections.shuffle(out);
        return out.size() > limit ? new ArrayList<>(out.subList(0, limit)) : out;
    }

    /**
     * The next never-verified address worth a quick reachability probe, or null. An address qualifies when we have
     * never connected to it, it is not a seed, banned, backed off or already connected, it is dialable (a Brontide
     * key on the standard Brontide port, or no key on the cleartext port) and it has not been probed within
     * {@code minGapMs}. Brontide-capable addresses come first, then the most recently announced.
     */
    public ConnectTarget nextProbeTarget(Set<String> connected, String selfIpNow,
                                         Map<String, Long> lastProbe, long minGapMs) {
        long now = System.currentTimeMillis();
        List<Peer> keyed = new ArrayList<>(), plain = new ArrayList<>();
        for (Peer p : peers.values()) {
            if (p.isSeed || p.successCount > 0 || pinned.contains(p.ip)) continue;
            if (p.ip.equals(selfIpNow) || connected.contains(p.ip)) continue;
            expireBan(p);
            if (p.banned || p.isBackedOff() || p.isBlacklisted()) continue;
            Long lp = lastProbe.get(p.ip);
            if (lp != null && now - lp < minGapMs) continue;
            if (p.hasBrontideKey()) { if (p.port == 44806) keyed.add(p); }
            else if (p.port == PLAIN_PORT) plain.add(p);
        }
        Comparator<Peer> newestFirst = (x, y) -> Long.compare(y.gossipTime, x.gossipTime);
        keyed.sort(newestFirst);
        plain.sort(newestFirst);
        for (Peer p : keyed) {
            byte[] kb = NodeIdentity.base32Decode(p.brontideKey);
            if (kb != null && kb.length == 33) return new ConnectTarget(p.ip, p.port, kb, "probe");
        }
        if (!plain.isEmpty()) return new ConnectTarget(plain.get(0).ip, plain.get(0).port, null, "probe");
        return null;
    }

    private static boolean isAllZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** True for a loopback / private / link-local / CGNAT / multicast IPv4 literal, or ::1. Anything that is not an
     *  IPv4 literal (an IPv6 seed, say) is NOT treated as non-public, so it is left alone. */
    private static boolean isNonPublic(String ip) {
        if (ip == null) return false;
        if (ip.equals("::1")) return true;
        if (!ip.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return false;
        return !isValidIp(ip);
    }

    private static boolean isValidIp(String ip) {
        if (ip == null) return false;
        if (ip.startsWith("0.") || ip.startsWith("127.") || ip.startsWith("192.168.")
                || ip.startsWith("10.") || ip.startsWith("169.254.")) return false;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        try {
            int[] v = new int[4];
            for (int i = 0; i < 4; i++) {
                v[i] = Integer.parseInt(parts[i]);
                if (v[i] < 0 || v[i] > 255) return false;
            }
            if (v[0] == 172 && v[1] >= 16 && v[1] <= 31) return false;   // private
            if (v[0] == 100 && v[1] >= 64 && v[1] <= 127) return false;  // carrier-grade NAT
            if (v[0] >= 224) return false;                                // multicast / reserved / broadcast
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // ── Peer selection ────────────────────────────────────────────────────────

    /** Seeds first (weighted among themselves), then everything else
     *  (weighted). Same two-tier priority PeerDiscovery.getCandidates()
     *  used to provide. */
    public List<ConnectTarget> getCandidates() {
        peers.values().forEach(this::expireBan);   // lift bans that have run their 24 h before choosing
        List<ConnectTarget> seedCandidates = new ArrayList<>();
        List<ConnectTarget> otherCandidates = new ArrayList<>();
        List<ConnectTarget> plainCandidates = new ArrayList<>();
        List<ConnectTarget> pinnedCandidates = new ArrayList<>();
        for (Peer p : peers.values()) {
            if (isSelf(p.ip, p.brontideKey)) continue;
            if (pinned.contains(p.ip) && !p.banned) {
                if (p.hasBrontideKey()) {
                    byte[] kb = NodeIdentity.base32Decode(p.brontideKey);
                    if (kb != null && kb.length == 33) {
                        pinnedCandidates.add(new ConnectTarget(p.ip, p.port, kb, "pinned"));
                        continue;
                    }
                } else if (p.port == PLAIN_PORT) {
                    pinnedCandidates.add(new ConnectTarget(p.ip, p.port, null, "pinned"));
                    continue;
                }
            }
            if (!p.hasBrontideKey()) {
                // Cleartext peer: only ever tried after every Brontide
                // candidate, and only on the standard cleartext port.
                if (p.port == PLAIN_PORT && !shouldSkip(p.ip)) {
                    plainCandidates.add(new ConnectTarget(p.ip, p.port, null, "cleartext"));
                }
                continue;
            }
            if (shouldSkip(p.ip)) continue;
            byte[] keyBytes = NodeIdentity.base32Decode(p.brontideKey);
            if (keyBytes == null || keyBytes.length != 33) continue;
            ConnectTarget target = new ConnectTarget(p.ip, p.port, keyBytes,
                    p.isSeed ? p.label : "discovered");
            if (p.isSeed) seedCandidates.add(target); else otherCandidates.add(target);
        }
        List<ConnectTarget> candidates = new ArrayList<>(pinnedCandidates);
        candidates.addAll(weightedOrderCandidates(seedCandidates));
        candidates.addAll(weightedOrderCandidates(otherCandidates));
        candidates.addAll(weightedOrderCandidates(plainCandidates));
        return candidates;
    }

    private List<ConnectTarget> weightedOrderCandidates(List<ConnectTarget> group) {
        if (group.isEmpty()) return group;
        List<String> order = weightedOrder(group.stream().map(ConnectTarget::ip).toList());
        group.sort(Comparator.comparingInt(c -> order.indexOf(c.ip())));
        return group;
    }

    // ── Score updates (unchanged semantics from PeerScorecard) ──────────────────

    /** Highest score this peer can ever reach. Cleartext (keyless) peers are
     *  capped well below healthy Brontide peers. */
    private static int scoreCeiling(Peer r) {
        return r.hasBrontideKey() ? SCORE_MAX : SCORE_PLAIN_CAP;
    }

    public void recordSuccess(String ip, String agent, int height) {
        recordSuccess(ip, agent, height, true);
    }

    /** @param brontide whether THIS connection was Brontide-encrypted. A
     *  cleartext connection earns only the base bonus, never the Brontide
     *  bonus, and can never lift a score above the cleartext cap (it also never
     *  lowers an existing higher score, e.g. a known Brontide peer that happens
     *  to dial us in cleartext). */
    public void recordSuccess(String ip, String agent, int height, boolean brontide) {
        Peer r = getOrCreate(ip);
        if (brontide) {
            r.score = Math.min(scoreCeiling(r), r.score + SCORE_SUCCESS_BONUS + SCORE_BRONTIDE_BONUS);
        } else {
            r.score = Math.max(r.score, Math.min(SCORE_PLAIN_CAP, r.score + SCORE_SUCCESS_BONUS));
        }
        r.successCount++;
        r.lastSuccessTime = System.currentTimeMillis();
        r.lastAgent       = agent;
        r.lastHeight      = height;
        r.usesBrontide    = brontide;
        r.backoffLevel    = Math.max(0, r.backoffLevel - 1);
        r.backoffUntil    = 0;
        persist(r);
    }

    public void recordLatency(String ip, long millis) {
        Peer r = getOrCreate(ip);
        r.avgLatencyMs = r.avgLatencyMs < 0
                ? millis
                : (LATENCY_EMA_ALPHA * millis + (1 - LATENCY_EMA_ALPHA) * r.avgLatencyMs);
        if (r.avgLatencyMs < SCORE_FAST_THRESHOLD_MS) {
            r.score = Math.min(scoreCeiling(r), r.score + SCORE_LATENCY_ADJUST);
        } else if (r.avgLatencyMs > SCORE_SLOW_THRESHOLD_MS) {
            r.score = Math.max(0, r.score - SCORE_LATENCY_ADJUST);
        }
        persist(r);
    }

    public void recordValidData(String ip) {
        Peer r = getOrCreate(ip);
        r.score = Math.min(scoreCeiling(r), r.score + SCORE_VALID_DATA_BONUS);
        r.validDataCount++;
        persist(r);
    }

    /** Remembers why a peer lost score (newest last, max 5) so the admin panel can show it. */
    private void notePenalty(Peer r, int delta, String what) {
        synchronized (r.penalties) {
            r.penalties.addLast(new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date())
                    + "  -" + delta + "  " + what);
            while (r.penalties.size() > 5) r.penalties.removeFirst();
        }
    }

    public List<String> recentPenalties(Peer r) {
        synchronized (r.penalties) { return new ArrayList<>(r.penalties); }
    }

    public void recordInvalidData(String ip, String reason) {
        Peer r = getOrCreate(ip);
        notePenalty(r, SCORE_INVALID_DATA_PENALTY, "invalid data: " + reason);
        r.score = Math.max(0, r.score - SCORE_INVALID_DATA_PENALTY);
        r.invalidDataCount++;
        persist(r);
        System.out.printf("[PeerTable] %s sent invalid data (score now %d): %s%n", ip, r.score, reason);
        if (pinned.contains(ip)) {
            lift(r);
            persist(r);
        } else if (r.score < SCORE_BACKOFF_THRESHOLD) {
            applyBackoff(r);
            persist(r);
        }
    }

    /** A short, human category for a connection-failure reason string (what the admin page groups by). */
    public static String failureKind(String reason) {
        if (reason == null || reason.isBlank()) return "";
        String r = reason.toLowerCase(Locale.ROOT);
        if (r.contains("connect timed out") || r.contains("connection timed out")) return "no response";
        if (r.contains("refused")) return "port closed";
        if (r.contains("no route") || r.contains("network is unreachable") || r.contains("unresolved")) return "no route";
        if (r.contains("handshake timeout") || r.contains("read timed out") || r.contains("timed out")) return "handshake timed out";
        if (r.contains("reset") || r.contains("eof") || r.contains("closed") || r.contains("broken pipe")
                || r.contains("zero bytes") || r.contains("only got")) return "closed on connect";
        if (r.contains("brontide") || r.contains("decrypt") || r.contains("act two") || r.contains("act 2")) return "Brontide handshake failed";
        return "other";
    }

    public void recordFailure(String ip, String reason) {
        // A failure for an address we do not know (a scanner or a stranger that failed an inbound handshake) must not
        // create a row: nothing would ever test it, and it would sit in the list as "unverified" forever.
        Peer r = peers.get(ip);
        if (r == null) return;
        // A gossip-discovered address we have never once connected to is not a "bad peer": it is most often a node
        // behind NAT, one whose inbound slots are full, or a stale entry. Count the failure and back off (so we do not
        // hammer it) but do not burn its score, so it can never be blacklisted -- only dropped after repeated failures.
        boolean neverVerified = !r.isSeed && r.successCount == 0 && !pinned.contains(ip);
        r.failureCount++;
        r.lastFailureTime = System.currentTimeMillis();
        r.lastFailureReason = reason == null ? "" : (reason.length() > 120 ? reason.substring(0, 120) : reason);
        if (neverVerified) {
            r.backoffLevel = Math.min(r.backoffLevel + 1, 2);   // 5 min, 30 min, then 2 h
            r.backoffUntil = System.currentTimeMillis() + BACKOFF_MS[r.backoffLevel];
        } else {
            notePenalty(r, SCORE_FAILURE_PENALTY, "failure: " + reason);
            r.score = Math.max(0, r.score - SCORE_FAILURE_PENALTY);
            if (pinned.contains(ip)) {
                lift(r);   // pinned: never backed off, score floored
            } else if (r.score < SCORE_BACKOFF_THRESHOLD) {
                applyBackoff(r);
            }
        }
        persist(r);
        if (r.isBlacklisted()) {
            System.out.printf("[PeerTable] %s blacklisted (score=%d, %s): %s%n", ip, r.score, r.status(), reason);
        } else if (r.isBackedOff()) {
            System.out.printf("[PeerTable] %s backoff %s: %s%n",
                    ip, formatDuration(r.backoffUntil - System.currentTimeMillis()), reason);
        }
    }

    /** Raises the displayed/known height for an existing peer (never lowers it, never creates a row).
     *  In-memory only: the next successful connect persists a fresh value anyway. */
    public void updateHeight(String ip, int height) {
        Peer r = peers.get(ip);
        if (r != null && height > r.lastHeight) r.lastHeight = height;
    }

    public void recordStaleTip(String ip, int peerHeight, int ourHeight) {
        Peer r = getOrCreate(ip);
        notePenalty(r, SCORE_STALE_TIP_PENALTY, "stale tip: peer " + peerHeight + " vs ours " + ourHeight);
        r.score = Math.max(0, r.score - SCORE_STALE_TIP_PENALTY);
        r.lastHeight = peerHeight;
        if (pinned.contains(ip)) lift(r);
        persist(r);
    }

    public void recordImplausibleTip(String ip, int claimedHeight, int consensusHeight) {
        Peer r = getOrCreate(ip);
        notePenalty(r, SCORE_IMPLAUSIBLE_TIP_PENALTY, "implausible tip claim " + claimedHeight + " (consensus ~" + consensusHeight + ")");
        r.score = Math.max(0, r.score - SCORE_IMPLAUSIBLE_TIP_PENALTY);
        persist(r);
        System.out.printf("[PeerTable] %s: implausible height claim %d (recent consensus ~%d), score now %d%n",
                ip, claimedHeight, consensusHeight, r.score);
    }

    public List<Peer> getRecentHeightObservations(long maxAgeMs) {
        long now = System.currentTimeMillis();
        List<Peer> result = new ArrayList<>();
        for (Peer r : peers.values()) {
            if (r.lastSuccessTime > 0 && (now - r.lastSuccessTime) <= maxAgeMs && r.lastHeight > 0) {
                result.add(r);
            }
        }
        return result;
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public boolean shouldSkip(String ip) {
        Peer r = peers.get(ip);
        if (r == null) return false;
        expireBan(r);
        if (pinned.contains(ip)) return r.banned;   // pinned: backoff never applies
        return r.banned || r.isBackedOff();
    }

    /** True only for an explicit ban (not backoff). Used to gate inbound connections. */
    public boolean isBanned(String ip) {
        Peer r = peers.get(ip);
        if (r != null) expireBan(r);
        return r != null && r.banned && !pinned.contains(ip);
    }

    /** hsd common.BAN_TIME: a ban lasts 24 hours, then the peer is eligible again. */
    public static final long BAN_DURATION_MS = 24L * 60 * 60 * 1000;

    /** Lifts r's ban if it has run its 24 hours. Cheap; called wherever the ban flag is consulted. */
    private void expireBan(Peer r) {
        if (r.banned && r.banTime > 0 && System.currentTimeMillis() - r.banTime >= BAN_DURATION_MS) {
            System.out.printf("[PeerTable] Ban on %s expired (%s)%n", r.ip, r.banReason);
            r.banned = false;
            r.banReason = null;
            persist(r);
        }
    }

    public void banPeer(String ip, String reason) {
        Peer r = getOrCreate(ip);
        r.banned = true;
        r.banReason = reason;
        r.banTime = System.currentTimeMillis();
        r.score = 0;
        persist(r);
        System.out.printf("[PeerTable] BANNED %s: %s%n", ip, reason);
    }

    public void unbanPeer(String ip) {
        Peer r = peers.get(ip);
        if (r != null) {
            r.banned = false;
            r.banReason = null;
            persist(r);
        }
    }

    /** Snapshot of every peer record (seeds, discovered, inbound-learned, banned...). */
    public List<Peer> listAllPeers() {
        List<Peer> all = new ArrayList<>(peers.values());
        all.removeIf(p -> isSelf(p.ip, p.brontideKey));
        return all;
    }

    public List<Peer> listBannedPeers() {
        peers.values().forEach(this::expireBan);
        return peers.values().stream().filter(r -> r.banned).toList();
    }

    public void clearAllBans() {
        for (Peer r : peers.values()) {
            if (r.banned) {
                r.banned = false;
                r.banReason = null;
                persist(r);
            }
        }
    }

    public boolean isGood(String ip) {
        Peer r = peers.get(ip);
        if (r != null && pinned.contains(ip)) return !r.banned;   // pinned bypasses the score floor
        return r == null || (!r.isBackedOff() && r.score >= SCORE_BACKOFF_THRESHOLD);
    }

    /** A peer below the dial threshold that is worth an occasional test dial: it has
     *  connected successfully before, isn't banned or in backoff. Without this, a
     *  formerly-good peer that fell under the threshold is never dialed again, so it
     *  can never earn its score back. */
    public boolean isRetryable(String ip) {
        Peer r = peers.get(ip);
        return r != null && !r.banned && !r.isBackedOff() && r.successCount > 0
                && r.hasBrontideKey() && r.score < SCORE_BACKOFF_THRESHOLD;
    }

    public List<Peer> getRankedPeers() {
        return peers.values().stream()
                .filter(r -> r.hasBrontideKey() || r.port == PLAIN_PORT)   // connectable peers only
                .filter(r -> !r.isBackedOff())
                .sorted((a, b) -> Integer.compare(b.score, a.score))
                .toList();
    }

    public List<String> weightedOrder(List<String> ips) {
        List<String> pool = new ArrayList<>(ips);
        List<Integer> weights = new ArrayList<>();
        for (String ip : pool) weights.add(Math.max(1, scoreOf(ip)));

        java.util.Random rnd = new java.util.Random();
        List<String> result = new ArrayList<>(pool.size());
        while (!pool.isEmpty()) {
            int total = weights.stream().mapToInt(Integer::intValue).sum();
            int r = rnd.nextInt(total);
            int cumulative = 0;
            int chosen = 0;
            for (int i = 0; i < weights.size(); i++) {
                cumulative += weights.get(i);
                if (r < cumulative) { chosen = i; break; }
            }
            result.add(pool.remove(chosen));
            weights.remove(chosen);
        }
        return result;
    }

    private int scoreOf(String ip) {
        Peer r = peers.get(ip);
        return r != null ? r.score : SCORE_INITIAL;
    }

    // ── Backoff ───────────────────────────────────────────────────────────────

    private void applyBackoff(Peer r) {
        int maxLevel = r.isSeed ? SEED_MAX_BACKOFF_LEVEL : BACKOFF_MS.length - 1;
        r.backoffLevel = Math.min(r.backoffLevel + 1, maxLevel);
        r.backoffUntil = System.currentTimeMillis() + BACKOFF_MS[r.backoffLevel];
        if (r.isSeed) {
            r.score = Math.max(r.score, SCORE_BACKOFF_THRESHOLD);
        }
    }

    public void resetAllBackoffs() {
        int reset = 0;
        for (Peer r : peers.values()) {
            if (r.isBackedOff() || r.isBlacklisted()) {
                r.backoffUntil = 0;
                r.backoffLevel = 0;
                r.score = Math.max(r.score, SCORE_BACKOFF_THRESHOLD);
                persist(r);
                reset++;
            }
        }
        if (reset > 0) System.out.printf("[PeerTable] Reset %d peer backoff(s).%n", reset);
    }

    /** A formerly-working peer whose score fell below the dial threshold can
     *  never earn points back (it is never dialed), so after this long
     *  without any activity it is given another chance. */
    private static final long RECOVERY_RETRY_MS = 60 * 60_000L;

    /**
     * Forgets gossip-learned addresses that have gone stale. Applies only to
     * peers that came from ADDR gossip, were never connected to, and are not
     * seeds / pinned / banned -- so anything with real history is untouched.
     * Removal is NOT a tombstone: if the node comes back, a later ADDR or its
     * own connection to us simply re-adds it.
     * @param legacyToo also drop gossip rows saved before timestamps were tracked
     */
    private void pruneGossip(boolean legacyToo) {
        long now = System.currentTimeMillis();
        int expired = 0, failed = 0, legacy = 0, undialable = 0, idle = 0;
        for (Peer r : new ArrayList<>(peers.values())) {
            if (r.isSeed || r.banned || r.successCount > 0 || pinned.contains(r.ip)) continue;
            boolean gossip = r.source != null && r.source.startsWith("addr:");
            // A never-verified address can only ever be tested on the standard Brontide port (with a key) or the
            // standard cleartext port (without one). Anything else could never become verified, so it would sit in
            // the list forever.
            boolean dialable = r.hasBrontideKey() ? r.port == 44806 : r.port == PLAIN_PORT;
            if (!dialable) {
                peers.remove(r.ip);
                if (peersMap != null) peersMap.remove(r.ip);
                undialable++;
                continue;
            }
            if (!gossip) {
                // Created by something other than gossip (an inbound attempt, an old version): drop it once it has
                // been quiet for a day, since nothing will ever test it.
                long last = Math.max(Math.max(r.lastAttemptTime, r.lastFailureTime), Math.max(r.gossipTime, r.discoveredAt));
                if (last == 0 || now - last > 24L * 3600_000L) {
                    peers.remove(r.ip);
                    if (peersMap != null) peersMap.remove(r.ip);
                    idle++;
                }
                continue;
            }
            boolean drop = false;
            if (r.gossipTime == 0) {
                if (legacyToo) { drop = true; legacy++; }
            } else if (now - r.gossipTime > ADDR_EXPIRE_MS) {
                drop = true; expired++;
            }
            if (!drop && r.failureCount >= ADDR_MAX_FAILURES) { drop = true; failed++; }
            if (drop) {
                if (r.failureCount >= ADDR_MAX_FAILURES) forget(r.ip);   // remember it, so re-gossip cannot bring it back
                else {
                    peers.remove(r.ip);
                    if (peersMap != null) peersMap.remove(r.ip);
                }
            }
        }
        int total = expired + failed + legacy + undialable + idle;
        if (total > 0) {
            if (peersMap != null) ConfigDB.get().commit();
            System.out.printf("[PeerTable] Forgot %d unverified address(es): %d failed %d+ dials (kept off the list for %d days), "
                            + "%d unseen >%dh, %d on a non-standard port, %d inactive non-gossip, %d pre-timestamp.%n",
                    total, failed, ADDR_MAX_FAILURES, FORGET_MS / (24L * 3600_000L),
                    expired, ADDR_EXPIRE_MS / 3600_000L, undialable, idle, legacy);
        }
    }

    public void applyDecay() {
        pruneGossip(false);
        long now = System.currentTimeMillis();
        for (Peer r : peers.values()) {
            if (r.successCount > 0 && !r.banned && r.score < SCORE_BACKOFF_THRESHOLD
                    && !r.isBackedOff()) {
                long ref = Math.max(Math.max(r.lastFailureTime, r.lastSuccessTime), r.lastRecoveryTime);
                if (now - ref >= RECOVERY_RETRY_MS) {
                    System.out.printf("[PeerTable] %s gets another chance (score %d -> %d, quiet for %d min).%n",
                            r.ip, r.score, SCORE_BACKOFF_THRESHOLD, (now - ref) / 60_000);
                    r.score = SCORE_BACKOFF_THRESHOLD;
                    r.lastRecoveryTime = now;   // restart the quiet period
                    persist(r);
                }
            }
            if (r.score < scoreCeiling(r) && r.lastSuccessTime > 0) {
                long minutesSinceSuccess = (now - r.lastSuccessTime) / 60_000;
                if (minutesSinceSuccess < 60) {
                    r.score = Math.min(scoreCeiling(r), r.score + 1);
                    persist(r);
                }
            }
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private Peer getOrCreate(String ip) {
        if (!peers.containsKey(ip) && isNonPublic(ip) && !pinned.contains(ip)) {
            return new Peer(ip);   // throw-away row: loopback/private callers are never stored or persisted
        }
        return peers.computeIfAbsent(ip, k -> {
            Peer p = new Peer(k);
            p.score = isSeed(k) ? SCORE_INITIAL : SCORE_INITIAL_DISCOVERED;
            return p;
        });
    }

    private void persist(Peer r) {
        if (peersMap != null && peers.get(r.ip) == r) {
            peersMap.put(r.ip, r.toStorage());
            ConfigDB.get().commit();
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static int parseIntSafe(String[] p, int i, int def) {
        if (i >= p.length) return def;
        try { return Integer.parseInt(p[i].trim()); } catch (Exception e) { return def; }
    }

    private static long parseLongSafe(String[] p, int i, long def) {
        if (i >= p.length) return def;
        try { return Long.parseLong(p[i].trim()); } catch (Exception e) { return def; }
    }

    private static String formatDuration(long ms) {
        if (ms <= 0) return "0s";
        long s = ms / 1000;
        if (s < 60)   return s + "s";
        if (s < 3600) return (s / 60) + "m";
        return (s / 3600) + "h " + ((s % 3600) / 60) + "m";
    }
}
