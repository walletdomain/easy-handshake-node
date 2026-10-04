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

    private static final double LATENCY_EMA_ALPHA        = 0.3;
    private static final double SCORE_FAST_THRESHOLD_MS  = 800;
    private static final double SCORE_SLOW_THRESHOLD_MS  = 5000;
    private static final int    SCORE_LATENCY_ADJUST     = 1;

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
        public boolean banned;             // in-memory only; permanent until process restart
        public String  banReason;          // in-memory only
        public long    banTime;            // in-memory only

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
                    + lastFailureTime + "|" + lastHeight + "|" + nz(lastAgent) + "|" + backoffUntil;
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
            return p;
        }

        private static String nz(String s) { return s != null ? s : ""; }

        @Override
        public String toString() {
            return (label.isBlank() ? ip : label + " (" + ip + ")") + ":" + port;
        }
    }

    /**
     * A peer we can attempt to connect to. brontideKey is always a real
     * 33-byte key -- only ever constructed once one is confirmed present.
     */
    public record ConnectTarget(String ip, int port, byte[] brontideKey, String label) {}

    // ── State ─────────────────────────────────────────────────────────────────

    private final ConcurrentHashMap<String, Peer> peers = new ConcurrentHashMap<>();
    private KVMap<String, String> peersMap;

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
            if (key.startsWith("deleted:")) continue; // tombstone, not a peer row
            peers.put(key, Peer.fromStorage(key, e.getValue()));
            loaded++;
        }
        if (loaded == 0) {
            migrateLegacyData(configDb, chainDb);
        }
        mergeFromResourceFile();
        resetAllBackoffs();
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

    private record SeedLine(String brontideKey, String ip, int port, String label) {}

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

    /** Adds a peer learned from ADDR gossip, an inbound connection, or RPC
     *  addnode. No-op if already known (seed or otherwise) or tombstoned --
     *  matches the old PeerDiscovery.addDiscovered()'s exact semantics. */
    public void addDiscovered(String brontideKey, String ip, int port, String source) {
        if (ip == null || ip.isBlank()) return;
        if (isDeleted(ip)) return;
        if (peers.containsKey(ip)) return; // already known, seed or otherwise
        Peer peer = new Peer(ip);
        peer.brontideKey  = brontideKey != null ? brontideKey : "";
        peer.port         = port;
        peer.source       = source;
        peer.discoveredAt = System.currentTimeMillis();
        peer.score        = SCORE_INITIAL_DISCOVERED;
        peers.put(ip, peer);
        peersMap.put(ip, peer.toStorage());
        ConfigDB.get().commit();
        System.out.printf("[PeerTable] Discovered peer: %s (%s)%n", ip, source);
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
        int entryCount = msg[0] & 0xFF;
        int newlyAdded = 0;
        int skippedWrongPort = 0;
        int skippedKeyless = 0;
        int skippedInvalidIp = 0;
        int skippedAlreadyKnown = 0;
        Integer samplePort = null;
        String sampleKeyHex = null;
        try {
            int pos = 1;
            for (int i = 0; i < entryCount && pos + 88 <= msg.length; i++) {
                pos += 8 + 4 + 4; // skip time + services + hiServices
                pos += 1;         // skip addrType
                byte[] ipBytes = new byte[4];
                System.arraycopy(msg, pos + 12, ipBytes, 0, 4);
                pos += 16;
                pos += 20; // skip reserved
                int port = (msg[pos] & 0xFF) | ((msg[pos + 1] & 0xFF) << 8);
                pos += 2;
                byte[] keyBytes = Arrays.copyOfRange(msg, pos, pos + 33);
                pos += 33;

                String ip = (ipBytes[0] & 0xFF) + "." + (ipBytes[1] & 0xFF)
                        + "." + (ipBytes[2] & 0xFF) + "." + (ipBytes[3] & 0xFF);
                if (!isValidIp(ip)) { skippedInvalidIp++; continue; }

                boolean wrongPort = port != 44806;
                boolean keyless = isAllZero(keyBytes);
                if (wrongPort || keyless) {
                    if (wrongPort) skippedWrongPort++;
                    if (keyless) skippedKeyless++;
                    if (samplePort == null) {
                        samplePort = port;
                        sampleKeyHex = toHex(keyBytes);
                    }
                    continue;
                }

                if (peers.containsKey(ip)) {
                    skippedAlreadyKnown++;
                    continue;
                }

                String base32Key = NodeIdentity.base32Encode(keyBytes);
                addDiscovered(base32Key, ip, port, "addr:" + fromIp);
                newlyAdded++;
            }
            System.out.printf("[PeerTable] ADDR from %s: %d entries (%d new, %d already known, "
                            + "%d wrong-port, %d keyless, %d invalid IP)%s.%n",
                    fromIp, entryCount, newlyAdded, skippedAlreadyKnown,
                    skippedWrongPort, skippedKeyless, skippedInvalidIp,
                    samplePort != null
                            ? String.format(" -- first rejected entry: port=%d key=%s", samplePort, sampleKeyHex)
                            : "");
        } catch (Exception e) {
            System.out.printf("[PeerTable] ADDR from %s: failed to parse "
                            + "(%d declared entries, %d byte payload): %s%n",
                    fromIp, entryCount, msg.length, e);
        }
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

    private static boolean isValidIp(String ip) {
        if (ip == null) return false;
        if (ip.startsWith("0.") || ip.startsWith("127.") || ip.startsWith("192.168.")
                || ip.startsWith("10.")) return false;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        try {
            int[] v = new int[4];
            for (int i = 0; i < 4; i++) {
                v[i] = Integer.parseInt(parts[i]);
                if (v[i] < 0 || v[i] > 255) return false;
            }
            if (v[0] == 172 && v[1] >= 16 && v[1] <= 31) return false;
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
        List<ConnectTarget> seedCandidates = new ArrayList<>();
        List<ConnectTarget> otherCandidates = new ArrayList<>();
        for (Peer p : peers.values()) {
            if (!p.hasBrontideKey()) continue;
            if (shouldSkip(p.ip)) continue;
            byte[] keyBytes = NodeIdentity.base32Decode(p.brontideKey);
            if (keyBytes == null || keyBytes.length != 33) continue;
            ConnectTarget target = new ConnectTarget(p.ip, p.port, keyBytes,
                    p.isSeed ? p.label : "discovered");
            if (p.isSeed) seedCandidates.add(target); else otherCandidates.add(target);
        }
        List<ConnectTarget> candidates = new ArrayList<>();
        candidates.addAll(weightedOrderCandidates(seedCandidates));
        candidates.addAll(weightedOrderCandidates(otherCandidates));
        return candidates;
    }

    private List<ConnectTarget> weightedOrderCandidates(List<ConnectTarget> group) {
        if (group.isEmpty()) return group;
        List<String> order = weightedOrder(group.stream().map(ConnectTarget::ip).toList());
        group.sort(Comparator.comparingInt(c -> order.indexOf(c.ip())));
        return group;
    }

    // ── Score updates (unchanged semantics from PeerScorecard) ──────────────────

    public void recordSuccess(String ip, String agent, int height) {
        Peer r = getOrCreate(ip);
        int bonus = SCORE_SUCCESS_BONUS + SCORE_BRONTIDE_BONUS;
        r.score           = Math.min(SCORE_MAX, r.score + bonus);
        r.successCount++;
        r.lastSuccessTime = System.currentTimeMillis();
        r.lastAgent       = agent;
        r.lastHeight      = height;
        r.usesBrontide    = true;
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
            r.score = Math.min(SCORE_MAX, r.score + SCORE_LATENCY_ADJUST);
        } else if (r.avgLatencyMs > SCORE_SLOW_THRESHOLD_MS) {
            r.score = Math.max(0, r.score - SCORE_LATENCY_ADJUST);
        }
        persist(r);
    }

    public void recordValidData(String ip) {
        Peer r = getOrCreate(ip);
        r.score = Math.min(SCORE_MAX, r.score + SCORE_VALID_DATA_BONUS);
        r.validDataCount++;
        persist(r);
    }

    public void recordInvalidData(String ip, String reason) {
        Peer r = getOrCreate(ip);
        r.score = Math.max(0, r.score - SCORE_INVALID_DATA_PENALTY);
        r.invalidDataCount++;
        persist(r);
        System.out.printf("[PeerTable] %s sent invalid data (score now %d): %s%n", ip, r.score, reason);
        if (r.score < SCORE_BACKOFF_THRESHOLD) {
            applyBackoff(r);
            persist(r);
        }
    }

    public void recordFailure(String ip, String reason) {
        Peer r = getOrCreate(ip);
        r.score = Math.max(0, r.score - SCORE_FAILURE_PENALTY);
        r.failureCount++;
        r.lastFailureTime = System.currentTimeMillis();
        if (r.score < SCORE_BACKOFF_THRESHOLD) {
            applyBackoff(r);
        }
        persist(r);
        if (r.isBlacklisted()) {
            System.out.printf("[PeerTable] %s blacklisted (score=%d, %s): %s%n", ip, r.score, r.status(), reason);
        } else if (r.isBackedOff()) {
            System.out.printf("[PeerTable] %s backoff %s: %s%n",
                    ip, formatDuration(r.backoffUntil - System.currentTimeMillis()), reason);
        }
    }

    public void recordStaleTip(String ip, int peerHeight, int ourHeight) {
        Peer r = getOrCreate(ip);
        r.score = Math.max(0, r.score - SCORE_STALE_TIP_PENALTY);
        r.lastHeight = peerHeight;
        persist(r);
    }

    public void recordImplausibleTip(String ip, int claimedHeight, int consensusHeight) {
        Peer r = getOrCreate(ip);
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
        return r != null && (r.banned || r.isBackedOff());
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

    public List<Peer> listBannedPeers() {
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
        return r == null || (!r.isBackedOff() && r.score >= SCORE_BACKOFF_THRESHOLD);
    }

    public List<Peer> getRankedPeers() {
        return peers.values().stream()
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

    public void applyDecay() {
        long now = System.currentTimeMillis();
        for (Peer r : peers.values()) {
            if (r.score < SCORE_MAX && r.lastSuccessTime > 0) {
                long minutesSinceSuccess = (now - r.lastSuccessTime) / 60_000;
                if (minutesSinceSuccess < 60) {
                    r.score = Math.min(SCORE_MAX, r.score + 1);
                    persist(r);
                }
            }
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private Peer getOrCreate(String ip) {
        return peers.computeIfAbsent(ip, k -> {
            Peer p = new Peer(k);
            p.score = isSeed(k) ? SCORE_INITIAL : SCORE_INITIAL_DISCOVERED;
            return p;
        });
    }

    private void persist(Peer r) {
        if (peersMap != null) {
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
