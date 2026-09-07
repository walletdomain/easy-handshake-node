package handshake.node;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PeerDiscovery — tracks peers discovered via ADDR messages and inbound
 * connections, making them available for outbound connection attempts.
    * <p>
 * Design principles:
 *   - Seeds (from SeedDatabase) are always available regardless of discovery
 *   - Discovered peers supplement seeds — more peers = better connectivity
 *   - No peer is stored permanently as blacklisted — backoff is PeerScorecard's job
 *   - Thread-safe: called from multiple P2P threads concurrently
 */
public class PeerDiscovery {

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static final PeerDiscovery INSTANCE = new PeerDiscovery();
    public static PeerDiscovery get() { return INSTANCE; }

    // ── Discovered peer record ────────────────────────────────────────────────

    public record DiscoveredPeer(
            String brontideKey,  // base32-encoded compressed pubkey, or empty
            String ip,
            int    port,
            long   discoveredAt,
            String source        // "inbound", "addr", "dns"
    ) {
        public boolean hasBrontideKey() {
            return brontideKey != null && !brontideKey.isBlank();
        }

        public String toStorage() {
            return brontideKey + "|" + port + "|" + discoveredAt + "|" + source;
        }

        public static DiscoveredPeer fromStorage(String ip, String s) {
            try {
                String[] p = s.split("\\|", 4);
                return new DiscoveredPeer(p[0], ip,
                        Integer.parseInt(p[1]),
                        Long.parseLong(p[2]),
                        p.length > 3 ? p[3] : "unknown");
            } catch (Exception e) {
                return new DiscoveredPeer("", ip, 44806,
                        System.currentTimeMillis(), "unknown");
            }
        }
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final ConcurrentHashMap<String, DiscoveredPeer> discovered =
            new ConcurrentHashMap<>();
    private ChainDB db;

    private PeerDiscovery() {}

    // ── Initialization ────────────────────────────────────────────────────────

    public void init(ChainDB db) {
        this.db = db;
        // Load previously discovered peers from DB
        // Peers are stored under "peer:ip" keys in the meta map
        int loaded = 0;
        for (var e : db.getAllPeers().entrySet()) {
            String ip = e.getKey();
            if (!SeedDatabase.get().isSeed(ip)) {
                discovered.put(ip, DiscoveredPeer.fromStorage(ip, e.getValue()));
                loaded++;
            }
        }
        System.out.printf("[PeerDiscovery] Loaded %d previously discovered peers.%n",
                loaded);
    }

    // ── Peer registration ─────────────────────────────────────────────────────

    /**
     * Adds a peer discovered via inbound Brontide connection.
     * We know their public key so we can connect back.
     */
    /** Looks up a known brontide key for a peer IP, if we have one --
     *  used when building our own ADDR responses, so peers we relay to
     *  others get their real key included (matching the real 88-byte
     *  NetAddress format) rather than always being reported as keyless. */
    /** True if this IP is known to us at all (regardless of whether we
     *  have a real brontide key for it) -- used for "is this a tracked
     *  peer" checks like getaddednodeinfo, which shouldn't require a
     *  key just to confirm a peer was registered. */
    public boolean isDiscovered(String ip) {
        return discovered.containsKey(ip);
    }

    public String getBrontideKeyByIp(String ip) {
        DiscoveredPeer p = discovered.get(ip);
        return (p != null && p.hasBrontideKey()) ? p.brontideKey() : null;
    }

    public void addDiscovered(String brontideKey, String ip, int port, String source) {
        if (ip == null || ip.isBlank()) return;
        if (SeedDatabase.get().isSeed(ip)) return; // seeds handled separately
        if (discovered.containsKey(ip)) return;    // already known

        DiscoveredPeer peer = new DiscoveredPeer(
                brontideKey, ip, port, System.currentTimeMillis(), source);
        discovered.put(ip, peer);
        persist(peer);

        System.out.printf("[PeerDiscovery] Discovered peer: %s (%s)%n", ip, source);
    }

    /**
     * Adds a cleartext-only peer (no Brontide key).
     * Used for peers that only support cleartext on port 12038.
     */
    public void addCleartext(String ip) {
        addDiscovered("", ip, 12038, "cleartext");
    }

    /**
     * Processes an ADDR message received from a peer, extracting new peer
     * IPs. Uses the real 88-byte NetAddress-per-entry format (matching
     * ChainSync.writeNetAddress exactly: time(8)+services(4)+hiServices(4)
     * +addrType(1)+raw(16)+reserved(20)+port(2)+key(33)) -- this replaces
     * an earlier, simplified 30-byte-per-entry format that had no room
     * for an actual key at all, meaning every discovered peer silently
     * carried an empty brontide key regardless of what the real message
     * contained. Accepts both port 44806 (Brontide, keyed) and 12038
     * (cleartext) entries now, rather than only 44806.
     */
    public void onAddrMessage(byte[] msg, String fromIp) {
        try {
            int pos = 0;
            if (pos >= msg.length) return;
            int count = msg[pos++] & 0xFF;
            for (int i = 0; i < count && pos + 88 <= msg.length; i++) {
                pos += 8 + 4 + 4; // skip time + services + hiServices
                pos += 1;         // skip addrType
                // raw[16]: standard IPv4-mapped IPv6 -- IP is the last 4 bytes
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
                if (!isValidIp(ip)) continue;

                boolean hasKey = !isAllZero(keyBytes);
                if (hasKey && port == 44806) {
                    String base32Key = NodeIdentity.base32Encode(keyBytes);
                    addDiscovered(base32Key, ip, port, "addr:" + fromIp);
                } else if (!hasKey && port == 12038) {
                    addDiscovered("", ip, port, "addr:" + fromIp);
                }
                // else: an unrecognized combination (e.g. keyed port 12038),
                // skip rather than guess.
            }
        } catch (Exception ignored) {}
    }

    private static boolean isAllZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    // ── Peer selection ────────────────────────────────────────────────────────

    /**
     * Returns available peers for outbound connection attempts, seeds
     * FIRST as a group (weighted among themselves), followed by
     * discovered peers (Brontide and cleartext) as a group after them.
     * This is a genuine two-tier priority, not one flat weighted pool --
     * with true weighted sampling, a large enough number of low-scored
     * discovered peers can still statistically dominate selection over a
     * handful of high-scored seeds purely by sheer count, which doesn't
     * match the actual expectation that the node connects quickly via
     * the known-good curated seeds by default, falling back to
     * discovered peers only when seeds aren't working.
     */
    public List<ConnectTarget> getCandidates() {
        List<ConnectTarget> seedCandidates = new ArrayList<>();
        for (SeedDatabase.Seed seed : SeedDatabase.get().getBrontideSeeds()) {
            if (!PeerScorecard.get().shouldSkip(seed.ip())) {
                byte[] keyBytes = NodeIdentity.base32Decode(seed.brontideKey());
                seedCandidates.add(new ConnectTarget(
                        seed.ip(), seed.port(), keyBytes, seed.label()));
            }
        }

        List<ConnectTarget> discoveredCandidates = new ArrayList<>();
        for (DiscoveredPeer peer : discovered.values()) {
            if (!peer.hasBrontideKey()) continue;
            if (PeerScorecard.get().shouldSkip(peer.ip())) continue;
            byte[] keyBytes = NodeIdentity.base32Decode(peer.brontideKey());
            if (keyBytes != null && keyBytes.length == 33) {
                discoveredCandidates.add(new ConnectTarget(
                        peer.ip(), peer.port(), keyBytes, "discovered"));
            }
        }
        discoveredCandidates.addAll(getCleartextCandidates());

        List<ConnectTarget> candidates = new ArrayList<>();
        candidates.addAll(weightedOrderCandidates(seedCandidates));
        candidates.addAll(weightedOrderCandidates(discoveredCandidates));
        return candidates;
    }

    private List<ConnectTarget> weightedOrderCandidates(List<ConnectTarget> group) {
        if (group.isEmpty()) return group;
        List<String> order = PeerScorecard.get().weightedOrder(
                group.stream().map(ConnectTarget::ip).toList());
        group.sort(Comparator.comparingInt(c -> order.indexOf(c.ip())));
        return group;
    }

    /**
     * Returns cleartext-only candidates (port 12038, no Brontide key).
     */
    public List<ConnectTarget> getCleartextCandidates() {
        List<ConnectTarget> candidates = new ArrayList<>();
        for (DiscoveredPeer peer : discovered.values()) {
            if (peer.port() == 12038 && !peer.hasBrontideKey()) {
                if (!PeerScorecard.get().shouldSkip(peer.ip())) {
                    candidates.add(new ConnectTarget(
                            peer.ip(), peer.port(), null, "cleartext"));
                }
            }
        }
        return candidates;
    }

    /**
     * A peer we can attempt to connect to.
     */
    public record ConnectTarget(
            String ip,
            int    port,
            byte[] brontideKey,  // null for cleartext
            String label
    ) {
        public boolean isBrontide() {
            return brontideKey != null && brontideKey.length == 33;
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public int getDiscoveredCount() { return discovered.size(); }

    public boolean isKnown(String ip) {
        return SeedDatabase.get().isSeed(ip) || discovered.containsKey(ip);
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private void persist(DiscoveredPeer peer) {
        if (db != null) {
            db.savePeer(peer.ip(), peer.toStorage());
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

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
            // 172.16.0.0/12 is the actual private range -- NOT all of
            // 172.x.x.x, which would incorrectly reject real public IPs
            // like 172.104.214.189 (one of our own seeds).
            if (v[0] == 172 && v[1] >= 16 && v[1] <= 31) return false;
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}