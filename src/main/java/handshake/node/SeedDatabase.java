package handshake.node;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * SeedDatabase — loads known Handshake seed nodes from ConfigDB's real
 * "seeds" map (recovered from an earlier version of this project),
 * replacing the previous hardcoded-in-Java list.
 * <p>
 * Real format found in the recovered data: for a key = ip, the value is
 *   brontideKey|port|source|<blank 4th field, meaning unconfirmed>|isBuiltin
 * A separate tombstone convention also exists: a key "deleted:<ip>" with
 * value "true" marks a seed as permanently removed (distinct from
 * PeerScorecard's temporary backoff) -- entries with such a tombstone
 * are skipped on load.
 * <p>
 * Design principles (unchanged from before):
 *   - Seeds are NEVER permanently blacklisted by THIS class — only
 *     temporarily backed off, and that's PeerScorecard's job, not this
 *     class's. The "deleted:" tombstone is a different, harder removal
 *     that was apparently made deliberately in the recovered data (e.g.
 *     to drop a seed that turned out to be unreliable) -- it isn't
 *     re-added here even though seeds are otherwise never blacklisted,
 *     since honoring an explicit prior removal is different from this
 *     class deciding to blacklist something itself.
 *   - New seeds discovered at runtime are persisted back into the same
 *     "seeds" map (isBuiltin=false) so they survive restarts.
 *   - Brontide-only: this project never tracks or connects to a keyless
 *     (cleartext) peer. Real hsd's own HostList.add() -- the code path
 *     that actually propagates a peer through the real network via ADDR
 *     gossip -- has no brontide-key requirement at all, so being
 *     keyed-only here doesn't reduce our own discoverability by other
 *     real nodes; it only means we don't bother tracking peers we could
 *     never connect to securely in the first place.
 */
public class SeedDatabase {

    // ── Seed record ───────────────────────────────────────────────────────────

    /**
     * A known seed validator.
     * <p>
     * @param brontideKey  Base32-encoded compressed secp256k1 public key (33 bytes).
     *                     Always required -- see the class comment on why this
     *                     project no longer tracks keyless (cleartext) seeds.
     * @param ip           IPv4 or IPv6 address
     * @param port         P2P port (always 44806, the Brontide port)
     * @param label        Human-readable label for logging
     * @param builtin      Whether this came from the curated seed set vs. runtime discovery
     */
    public record Seed(
            String brontideKey,
            String ip,
            int    port,
            String label,
            boolean builtin
    ) {
        public boolean hasBrontideKey() {
            return brontideKey != null && !brontideKey.isBlank();
        }

        String toStorage() {
            return brontideKey + "|" + port + "|" + label + "||" + builtin;
        }

        static Seed fromStorage(String ip, String s) {
            String[] p = s.split("\\|", -1);
            String key = p.length > 0 ? p[0] : "";
            int port = p.length > 1 ? parseIntSafe(p[1], 44806) : 44806;
            String label = p.length > 2 ? p[2] : "seed";
            boolean builtin = p.length > 4 && "true".equalsIgnoreCase(p[4]);
            return new Seed(key, ip, port, label, builtin);
        }

        private static int parseIntSafe(String s, int def) {
            try { return Integer.parseInt(s.trim()); } catch (Exception e) { return def; }
        }

        @Override
        public String toString() {
            return label + " (" + ip + ":" + port + ")";
        }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────
    //
    // Lazily initialized on first get() rather than eagerly at class-load
    // time, since it depends on ConfigDB already being open (NodeConfig.load()
    // opens it during normal startup, which happens before anything calls
    // SeedDatabase.get() in Main.java's sequence -- but unlike the previous
    // version's static-init bug, this fails loudly if that ordering is ever
    // violated instead of silently crashing or reading empty data.

    private static volatile SeedDatabase instance;

    public static SeedDatabase get() {
        if (instance == null) {
            synchronized (SeedDatabase.class) {
                if (instance == null) instance = new SeedDatabase();
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final KVMap<String, String> seedsMap;
    private final List<Seed> seeds = new CopyOnWriteArrayList<>();

    private SeedDatabase() {
        ConfigDB db;
        try {
            db = ConfigDB.get();
        } catch (IllegalStateException e) {
            throw new IllegalStateException(
                    "SeedDatabase.get() was called before ConfigDB was opened "
                            + "(NodeConfig.load(dataDir) must run first)", e);
        }
        this.seedsMap = db.seedsMap();
        loadFromDb();
        mergeFromResourceFile();
    }

    private void loadFromDb() {
        int loaded = 0, skippedDeleted = 0;
        for (var entry : seedsMap.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("deleted:")) continue; // tombstones handled below
            String ip = key;
            if (isDeleted(ip)) {
                skippedDeleted++;
                continue;
            }
            seeds.add(Seed.fromStorage(ip, entry.getValue()));
            loaded++;
        }
        System.out.printf("[SeedDB] Loaded %d seeds from the config database (%d tombstoned/skipped).%n",
                loaded, skippedDeleted);
    }

    private boolean isDeleted(String ip) {
        return "true".equalsIgnoreCase(seedsMap.get("deleted:" + ip));
    }

    // ── Bootstrap seeds ───────────────────────────────────────────────────────
    //
    // FIX: moved out of hardcoded Java (previously a BOOTSTRAP_SEEDS
    // List.of(...) literal right here, requiring a recompile to add,
    // remove, or fix a single seed -- e.g. dropping a seed that turns
    // out to reliably fail its handshake, or shipping a newly found
    // reliable one) and into seeds.txt on the classpath, following the
    // exact same convention ReservedNames.java already uses for
    // reserved_lockup.tsv: a plain, human-editable resource file loaded
    // via getResourceAsStream(), failing loudly (not silently) if it's
    // missing from the classpath.
    //
    // FIX: no longer only consulted on a genuinely fresh install (empty
    // seeds map). Now merged in on EVERY startup, so that shipping an
    // updated seeds.txt (fixing a bad entry, adding a new reliable one)
    // actually reaches installs that have already run before, not just
    // brand new ones. This merge is deliberately additive-only and
    // respects everything this class already knows: an IP already
    // present in the persistent seeds map is left completely untouched
    // (whatever PeerScorecard/runtime discovery has learned about it
    // stays exactly as it was), and an IP with a "deleted:<ip>"
    // tombstone is never resurrected just because it's still listed in
    // seeds.txt -- removing a seed is done by tombstoning it (or simply
    // letting scoring back it off), never by editing this file, since a
    // node that already knows better about a given IP shouldn't be
    // overridden by the shipped defaults on its next restart.
    private static List<Seed> loadSeedsFromResource() {
        List<Seed> loaded = new ArrayList<>();
        try (InputStream in = SeedDatabase.class.getResourceAsStream("/seeds.txt")) {
            if (in == null) {
                throw new IllegalStateException(
                        "seeds.txt is missing from the classpath -- this project has no other "
                                + "way to find its first peer on a fresh install. See SeedDatabase's "
                                + "own class comment for where this file comes from and its format.");
            }
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                int lineNum = 0;
                while ((line = reader.readLine()) != null) {
                    lineNum++;
                    String trimmed = line.trim();
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                    String[] p = trimmed.split("\\|", -1);
                    if (p.length < 4) {
                        System.err.printf("[SeedDB] seeds.txt line %d malformed (expected "
                                + "brontideKey|ip|port|label) -- skipping: %s%n", lineNum, line);
                        continue;
                    }
                    String brontideKey = p[0].trim();
                    String ip = p[1].trim();
                    int port = Seed.parseIntSafe(p[2].trim(), 44806);
                    String label = p[3].trim();
                    if (brontideKey.isEmpty() || ip.isEmpty()) {
                        System.err.printf("[SeedDB] seeds.txt line %d missing brontideKey or ip -- "
                                + "skipping: %s%n", lineNum, line);
                        continue;
                    }
                    loaded.add(new Seed(brontideKey, ip, port, label, true));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load seeds.txt", e);
        }
        return loaded;
    }

    private void mergeFromResourceFile() {
        List<Seed> fromFile = loadSeedsFromResource();
        int added = 0, alreadyKnown = 0, tombstoned = 0;
        for (Seed seed : fromFile) {
            if (isDeleted(seed.ip())) {
                tombstoned++;
                continue;
            }
            if (isSeed(seed.ip())) {
                alreadyKnown++;
                continue;
            }
            seeds.add(seed);
            seedsMap.put(seed.ip(), seed.toStorage());
            added++;
        }
        if (added > 0) {
            ConfigDB.get().commit();
        }
        System.out.printf("[SeedDB] seeds.txt: %d merged in, %d already known, %d tombstoned/skipped "
                + "(%d total seeds now).%n", added, alreadyKnown, tombstoned, seeds.size());
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Returns only Brontide-capable seeds. */
    public List<Seed> getBrontideSeeds() {
        return seeds.stream()
                .filter(Seed::hasBrontideKey)
                .toList();
    }

    /** Returns the seed for a given IP, or null. */
    public Seed getSeedByIp(String ip) {
        return seeds.stream()
                .filter(s -> s.ip().equals(ip))
                .findFirst()
                .orElse(null);
    }

    /** Returns true if the IP is a known (non-deleted) seed. */
    public boolean isSeed(String ip) {
        return seeds.stream().anyMatch(s -> s.ip().equals(ip));
    }

    /**
     * Adds a dynamically discovered seed (e.g. from ADDR messages) and
     * persists it into the config database's "seeds" map (isBuiltin=false) so it
     * survives restarts. Only added if not already known or previously
     * deleted.
     */
    public void addDiscovered(String brontideKey, String ip, int port, String label) {
        if (isSeed(ip) || isDeleted(ip)) return;
        Seed seed = new Seed(brontideKey, ip, port, label, false);
        seeds.add(seed);
        seedsMap.put(ip, seed.toStorage());
        ConfigDB.get().commit();
    }

    public int size() { return seeds.size(); }
}