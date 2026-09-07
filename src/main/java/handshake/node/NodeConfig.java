package handshake.node;

import org.h2.mvstore.MVMap;

/**
 * NodeConfig — configuration management for the Handshake node node.
 * <p>
 * Backed by ConfigDB's "settings" H2 map (recovered from an earlier,
 * more unified version of this project -- a desktop app with toggleable
 * full_node/dns/miner/wallet modules -- rather than the plain node.conf
 * properties file this class used before). Existing keys are read as-is;
 * any key this class needs that isn't already present gets a default
 * value written in (without touching keys it doesn't recognize).
 * <p>
 * RESOLVED AMBIGUITY: the recovered settings map also has "http.port"/
 * "http.bind" (8888 / 127.0.0.1), which turned out to be for a web
 * dashboard from that earlier, more unified project. This project is
 * intentionally a lean, RPC-only node -- no web server, no dashboard,
 * no TLS -- so those keys are no longer exposed here at all.
 * getRpcPort()/getRpcHost() keep their own "rpc.port"/"rpc.host" keys
 * and original defaults (12037 / 127.0.0.1, matching hsd's real RPC
 * port convention).
 */
public class NodeConfig {

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile NodeConfig instance;

    public static NodeConfig load(String dataDir) {
        if (instance == null) {
            synchronized (NodeConfig.class) {
                if (instance == null) instance = new NodeConfig(dataDir);
            }
        }
        return instance;
    }

    public static NodeConfig get() {
        if (instance == null) throw new IllegalStateException("NodeConfig not loaded");
        return instance;
    }

    // ── Defaults ──────────────────────────────────────────────────────────────

    private static final String DEFAULT_NETWORK      = "mainnet";
    private static final int    DEFAULT_P2P_PORT      = 44806;
    private static final int    DEFAULT_RPC_PORT      = 12037;
    private static final int    DEFAULT_SOCKET_PORT   = 12040;
    private static final int    DEFAULT_WEB_ADMIN_PORT = 12080;
    private static final String DEFAULT_RPC_HOST      = "127.0.0.1";
    private static final String DEFAULT_API_KEY       = "";
    private static final int    DEFAULT_MAX_INBOUND   = 50;
    private static final int    DEFAULT_MAX_OUTBOUND  = 8;
    private static final boolean DEFAULT_INDEX_ADDR   = true;
    private static final boolean DEFAULT_INDEX_TX     = true;
    private static final String DEFAULT_LOG_LEVEL     = "info";
    /** Empty by default, matching real hsd's own convention -- hsd's
     *  user-agent comment (its own equivalent of a `-uacomment` flag) is
     *  only present if an operator explicitly sets one, not a random
     *  default. Appended to VERSION in ChainSync's P2P user-agent string
     *  as "/easy-handshake-node:VERSION/comment/" when non-empty, same
     *  as how a real hsd peer might show "/hsd:8.0.0/SomeOperatorName/". */
    private static final String DEFAULT_USERAGENT_COMMENT = "";

    /** The single, authoritative version string for this software --
     *  referenced by the console startup banner, the P2P user-agent
     *  (ChainSync), and the RPC subversion/version fields (RpcServer),
     *  so these can't drift out of sync with each other the way an
     *  earlier hardcoded "v0.1.0" vs "1.0.0" mismatch did. */
    public static final String VERSION = "1.0.0";

    // ── State ─────────────────────────────────────────────────────────────────

    private final String dataDir;
    private final MVMap<String, String> settings;

    // ── Constructor ───────────────────────────────────────────────────────────

    private NodeConfig(String dataDir) {
        this.dataDir  = dataDir;
        this.settings = ConfigDB.open(dataDir).settingsMap();
        System.out.println("[Config] Loaded " + settings.size() + " settings from config_mv.db");
    }

    // ── Getters ───────────────────────────────────────────────────────────────

    public String  getDataDir()     { return dataDir; }
    public String  getNetwork()     { return get("network",    DEFAULT_NETWORK); }
    public int     getP2pPort()     { return getInt("p2p.port",    DEFAULT_P2P_PORT); }
    public int     getRpcPort()     { return getInt("rpc.port",    DEFAULT_RPC_PORT); }
    /** Dedicated port for the Brontide-encrypted WebSocket event/call
     *  server -- separate from RPC's port since Java's built-in HTTP
     *  server has no clean way to intercept a raw socket for a
     *  protocol-upgrade path alongside its own normal request handling. */
    public int     getSocketPort()  { return getInt("socket.port", DEFAULT_SOCKET_PORT); }
    /** Always bound to the loopback interface only, regardless of this
     *  port's value -- there's no legitimate case for this admin
     *  interface to be reachable remotely, so making the bind address
     *  itself configurable would only add risk with no real benefit. */
    public int     getWebAdminPort() { return getInt("webadmin.port", DEFAULT_WEB_ADMIN_PORT); }
    public String  getRpcHost()     { return get("rpc.host",       DEFAULT_RPC_HOST); }
    public String  getApiKey()      { return get("rpc.api.key",    DEFAULT_API_KEY); }
    public int     getMaxInbound()  { return getInt("max.inbound",  DEFAULT_MAX_INBOUND); }
    public int     getMaxOutbound() { return getInt("max.outbound", DEFAULT_MAX_OUTBOUND); }
    public boolean indexAddress()   { return getBool("index.address", DEFAULT_INDEX_ADDR); }
    public boolean indexTx()        { return getBool("index.tx",      DEFAULT_INDEX_TX); }
    public String  getLogLevel()    { return get("log.level",      DEFAULT_LOG_LEVEL); }
    /** Stored in the config database now, as requested -- editable via
     *  the admin panel is a natural follow-up, not built yet. */
    public String  getUserAgentComment() { return get("p2p.useragent.comment", DEFAULT_USERAGENT_COMMENT); }
    public void    setUserAgentComment(String comment) { set("p2p.useragent.comment", comment); }

    // Informational module toggles, present in the recovered settings map.
    // Not currently consulted by any class in this project (this is a
    // single-purpose node build), but exposed since the data is there.
    public boolean isFullNodeModuleEnabled() { return getBool("module.full_node", true); }
    public boolean isDnsModuleEnabled()      { return getBool("module.dns", false); }
    public boolean isMinerModuleEnabled()    { return getBool("module.miner", false); }
    public boolean isWalletModuleEnabled()   { return getBool("module.wallet", false); }

    public boolean isMainnet() { return "mainnet".equals(getNetwork()); }

    /** Returns true if an API key is configured (RPC requires auth). */
    public boolean hasApiKey() {
        String key = getApiKey();
        return key != null && !key.isBlank();
    }

    // ── Setters ───────────────────────────────────────────────────────────────

    /** All raw settings as a plain map, for the settings dashboard page. */
    public java.util.Map<String, String> getAllSettings() {
        return new java.util.LinkedHashMap<>(settings);
    }

    public void set(String key, String value) {
        settings.put(key, value);
        ConfigDB.get().commit();
    }

    public void setApiKey(String key) {
        set("rpc.api.key", key);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    //
    // get/getInt/getBool are "read, or default-and-persist if missing" --
    // they only ever add keys this class doesn't find, never overwrite an
    // existing value from the real settings data.

    private String get(String key, String def) {
        String v = settings.get(key);
        if (v == null) {
            settings.put(key, def);
            return def;
        }
        return v;
    }

    private int getInt(String key, int def) {
        String v = settings.get(key);
        if (v == null) {
            settings.put(key, String.valueOf(def));
            return def;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private boolean getBool(String key, boolean def) {
        String v = settings.get(key);
        if (v == null) {
            settings.put(key, String.valueOf(def));
            return def;
        }
        return "true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v);
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    @Override
    public String toString() {
        return String.format(
                "NodeConfig{network=%s, p2p=%d, rpc=%s:%d, indexAddr=%b, indexTx=%b}",
                getNetwork(), getP2pPort(), getRpcHost(), getRpcPort(),
                indexAddress(), indexTx());
    }
}