package handshake.node.storage;

import java.io.File;
import java.util.Map;

/**
 * ConfigDB — owns the shared storage engine handle that holds validator
 * configuration, seed addresses, and peer scores (settings / seeds /
 * peerScores maps).
 * <p>
 * This exists because all three of those maps live in ONE physical
 * database, and a single storage engine handle only allows one open
 * instance at a time -- NodeConfig, SeedDatabase, and PeerScorecard
 * can't each open their own handle on the same underlying data
 * independently. This class is the single owner; the other three
 * classes go through it, entirely via the KVStore/KVMap abstraction --
 * none of them know or care which concrete engine is actually
 * underneath.
 * <p>
 * Directory name: kept as "config" for continuity with the file this
 * used to be (the recovered database was literally named
 * "config_mv.db") -- now a RocksDB directory rather than a single H2
 * file, matching ChainDB's own migration for the same reasons (see
 * RocksDBKVStore's own class comment).
 */
public final class ConfigDB {

    private static volatile ConfigDB instance;

    public static synchronized ConfigDB open(String dataDir) {
        if (instance == null) {
            instance = new ConfigDB(dataDir);
        }
        return instance;
    }

    public static ConfigDB get() {
        if (instance == null) throw new IllegalStateException("ConfigDB not opened");
        return instance;
    }

    private final KVStore store;
    private final KVMap<String, String> settings;
    private final KVMap<String, String> seeds;
    private final KVMap<String, String> peerScores;
    private final KVMap<String, String> peers;

    private ConfigDB(String dataDir) {
        String path = dataDir + "/config";
        File parent = new File(path).getParentFile();
        if (parent != null) parent.mkdirs();

        this.store = new RocksDBKVStore(path);
        this.settings = store.openStringStringMap("settings");
        this.seeds = store.openStringStringMap("seeds");
        this.peerScores = store.openStringStringMap("peerScores");
        // NEW: unified peer table storage (handshake.node.peer.PeerTable),
        // replacing the old seeds/peerScores/ChainDB-peers split. The old
        // maps above are left opened and untouched on disk so
        // PeerTable.migrateLegacyData() can read them once at startup.
        this.peers = store.openStringStringMap("peers");
        // FIX: a "discoveredPeers" map used to be opened here too, but it
        // was dead -- confirmed via grep across the whole codebase to
        // have no accessor and no reader/writer anywhere, apparently a
        // planned-but-never-implemented feature distinct from the real,
        // actively-used seeds map. Removed as part of the project's
        // dead-code cleanup pass. Safe even if a "discoveredPeers" column
        // family already exists on disk from a previous run: RocksDBKVStore
        // discovers and opens every existing column family at startup
        // regardless of which ones application code asks for by name
        // (see its own class comment) -- it just sits there unused, as it
        // already effectively was.
    }

    public KVMap<String, String> settingsMap() { return settings; }
    public KVMap<String, String> seedsMap() { return seeds; }
    public KVMap<String, String> peerScoresMap() { return peerScores; }
    public KVMap<String, String> peersMap() { return peers; }

    public void commit() {
        store.commit();
    }

    public void close() {
        store.close();
    }
}