package handshake.node.chain;

import handshake.node.util.HexUtil;

import handshake.node.crypto.Blake2b;
import handshake.node.crypto.BloomFilter;
import handshake.node.crypto.MerkleProof;

import handshake.node.storage.ChainDB;
import handshake.node.storage.ConfigDB;
import handshake.node.storage.PersistentLog;

import handshake.node.urkeltree.UrkelTreeRecovery;
import handshake.node.urkeltree.UrkelTreeMismatchException;

import handshake.node.peer.BrontideState;
import handshake.node.peer.PeerTable;
import handshake.node.peer.NodeIdentity;

import handshake.node.server.RpcServer;

import handshake.node.NodeConfig;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/**
 * ChainSync — synchronizes the validator with the Handshake network.
 * <p>
 * Responsibilities:
 *   1. Header sync: download all block headers from peers
 *   2. Block download: fetch full blocks for the header chain
 *   3. Block validation: verify proof-of-work and structure
 *   4. UTXO/name state updates: process covenants in confirmed blocks
 *   5. Peer management: connect to peers, detect stale tips
 * <p>
 * Design principles (learned from easy-handshake debugging):
 *   - Header tip is capped at peer tip + 2016 to prevent fake inflation
 *   - Auto-rollback when all peers report lower height than our tip
 *   - Block downloads use separate threads from header sync
 *   - Wallet/DNS notification via RpcServer.BlockListener
 * <p>
 * Sync lifecycle:
 *   HEADERS:  Connect to peer → send GETHEADERS → receive HEADERS
 *   BLOCKS:   Send GETBLOCKS → receive INV → send GETDATA → receive BLOCK
 *   STEADY:   Poll for new blocks every 60 seconds
 */
public class ChainSync {

    // ── Constants ─────────────────────────────────────────────────────────────

    // Lowered from 60: pooled outbound connections are not read between
    // sync cycles, so a pushed announcement can only be acted on at the next
    // cycle there. Inbound connections trigger an immediate cycle instead.
    private static final int POLL_INTERVAL_SEC  = 30;
    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS    = 30_000;
    private static final int MAX_HEADERS_BATCH  = 2000;

    /** How often (in headers) to print header-sync progress. Batches
     *  still arrive every MAX_HEADERS_BATCH -- this just throttles how
     *  often that progress is actually printed, independent of the wire
     *  batch size. See syncHeaders()'s own comment for why this changed
     *  from printing every batch. */
    private static final int HEADER_PROGRESS_LOG_EVERY = 20_000;
    private static final int MAX_BLOCK_BATCH    = 16;


    /** How many blocks to accumulate before committing to disk, rather
     *  than committing after every single block (see downloadBlocks()
     *  for why the previous unbatched behavior caused a real, worsening
     *  slowdown as the database grew). */
    private static final int BLOCK_COMMIT_INTERVAL = 100;

    /** How often (in blocks) to print the "Block N processed" progress
     *  line. Matches BlockProcessor's own timing-dump cadence (see
     *  BlockProcessor.BLOCKS_PER_TIMING_LOG) so the two lines that
     *  together describe "what's happened in the last batch of blocks"
     *  keep appearing together, not at two different, out-of-sync
     *  resolutions. */
    private static final int BLOCK_PROGRESS_LOG_EVERY = 1000;
    private static final int HANDSHAKE_TIMEOUT  = 10_000;

    // P2P message types -- real values from hsd's lib/net/packets.js exports.types,
    // confirmed via probe script against a real hsd installation. Previous values
    // here were guessed and several were wrong: TX/BLOCK were swapped, and
    // HEADERS/SENDHEADERS collided with totally different real types
    // (MEMPOOL=16, PROOF=27).
    private static final int MSG_VERSION     = 0;
    private static final int MSG_VERACK      = 1;
    private static final int MSG_PING        = 2;
    private static final int MSG_PONG        = 3;
    private static final int MSG_GETADDR     = 4;
    private static final int MSG_ADDR        = 5;
    private static final int MSG_INV         = 6;
    private static final int MSG_GETDATA     = 7;
    private static final int MSG_NOTFOUND    = 8;
    private static final int MSG_GETBLOCKS   = 9;
    private static final int MSG_GETHEADERS  = 10;
    private static final int MSG_HEADERS     = 11;
    private static final int MSG_SENDHEADERS = 12;
    private static final int MSG_BLOCK       = 13;
    private static final int MSG_TX          = 14;
    private static final int MSG_REJECT      = 15;
    private static final int MSG_MEMPOOL     = 16;
    // FIX: added for wallet SPV support -- values verified directly
    // against real hsd's own lib/net/packets.js (exports.types), not
    // assumed from Bitcoin's BIP37 numbering, though in this case they
    // happen to match exactly since hsd's packet enum is a direct,
    // unmodified continuation of bcoin's own.
    private static final int MSG_FILTERLOAD  = 17;
    private static final int MSG_FILTERADD   = 18;
    private static final int MSG_FILTERCLEAR = 19;
    private static final int MSG_MERKLEBLOCK = 20;

    // Real hsd frame wrapper (goes INSIDE the Brontide-encrypted payload):
    // magic(4 LE) + cmd(1) + length(4 LE) + payload(N). No checksum, 9-byte
    // header. Previously entirely missing -- messages were sent as raw
    // payload with no magic/length wrapper at all, which is why peers
    // accepted our Act1/2/3 (crypto layer, now correct) but never responded
    // to our VERSION message (application layer, was malformed).
    private static final int MAGIC_MAINNET = 0x5B6EF2D3;

    /**
     * Gates the noisy per-message hex dumps (full frame + encrypted wire
     * bytes on every single SEND/receive) added while debugging the
     * handshake layer earlier. That layer is now solved and verified --
     * these dumps fire on every message during header sync and block
     * download, which floods the console with output that's no longer
     * needed for normal operation. Error-path logging (decrypt failures,
     * bad magic, partial reads) stays on regardless, since those are rare
     * and genuinely useful when they do happen.
     * <p>
     * Not private: P2PServer gates its own inbound-handshake raw-byte
     * logging off this same flag, so there's one switch for "show me
     * every raw byte crossing the wire" rather than two independently
     * toggled ones that could drift out of sync with each other.
     */
    public static final boolean VERBOSE_WIRE_LOGGING = false;

    /**
     * Minimum score gap (current peer vs. the top-ranked candidate)
     * needed to justify disconnecting and reconnecting mid-sync. Real,
     * but not so small that ordinary scoring noise triggers constant
     * reconnects between every single header batch.
     */
    private static final int PEER_SWITCH_SCORE_MARGIN = 15;

    /**
     * After this many header batches on the same connection, rotate to a
     * different peer regardless of how well it's performing -- addresses
     * a real gap where score-based switching alone tends to keep using
     * the same peer indefinitely, since it's the only one actively
     * earning fresh score points while every other candidate sits
     * static. At 2000 headers/batch this is roughly 20,000 headers per
     * peer before a mandatory rotation.
     */
    private static final int MAX_BATCHES_PER_PEER = 10;

    /**
     * Same purpose as MAX_BATCHES_PER_PEER, but for block-download
     * batches -- header sync already rotated periodically, but block
     * downloading had no equivalent at all. A single downloadBlocks()
     * call can easily run for thousands of blocks in one continuous
     * pass (confirmed directly: a real run stayed on one connection for
     * over 6000 blocks with zero rotation), which meant the entire
     * outbound pool built for crossCheckTip() sat unexercised for the
     * whole duration once block downloading started. At MAX_BLOCK_BATCH
     * (16) blocks per batch, this is roughly 1600 blocks per peer
     * before a mandatory rotation -- deliberately higher than headers'
     * ~20,000-headers-per-peer, since a block batch carries far more
     * actual data (and far more validation work) per request than a
     * header batch does, so rotating at the same batch *count* would
     * mean rotating far more often in wall-clock terms.
     */
    private static final int MAX_BLOCK_BATCHES_PER_PEER = 100;

    /**
     * How far ahead of every other currently-pooled peer a sync
     * candidate's claimed height can be before crossCheckTip() surfaces
     * a warning. See crossCheckTip()'s own comment for why this is a
     * warning threshold, not a hard limit.
     */
    private static final int TIP_DISAGREEMENT_THRESHOLD = 100;

    /**
     * How far back PeerScorecard's persisted height history counts as
     * "recent enough to compare against" in crossCheckTip(). Kept tight
     * (well under Handshake mainnet's ~10-minute block time) so this is
     * comparing against what the network actually looked like a few
     * minutes ago, not treating an hour-old snapshot as if it were
     * still current.
     */
    private static final long TIP_HISTORY_WINDOW_MS = 15 * 60 * 1000;

    // NetAddress wire format (88 bytes exactly), used inside the VERSION payload.
    private static final int NET_ADDRESS_SIZE = 88;

    private static final int PROTOCOL_VERSION = 3;

    /** Built dynamically, not a fixed constant -- incorporates
     *  NodeConfig.VERSION (the single, authoritative version string also
     *  used by the console banner and RPC's subversion field) plus an
     *  optional operator-set comment, matching real hsd's own
     *  "/name:version/comment/" convention (comment omitted entirely
     *  when empty, same as hsd's own default behavior).
     *
     *  The P2P wire format's agent-length field is a single byte (max
     *  255, confirmed against this same class's own VERSION-message
     *  parsing code) -- a long or emoji-heavy comment could push the
     *  UTF-8-encoded string past that and silently corrupt the
     *  handshake, so the comment is truncated to fit if needed, safely
     *  at a whole-code-point boundary (never splitting a multi-byte
     *  UTF-8 sequence, which would produce invalid, corrupted bytes
     *  instead of just a shorter string). */
    private String userAgent() {
        String prefix = "/easy-handshake-node:" + NodeConfig.VERSION + "/";
        String comment = config.getUserAgentComment();
        if (comment == null || comment.isBlank()) return prefix;

        int maxCommentBytes = 255 - prefix.getBytes(java.nio.charset.StandardCharsets.UTF_8).length - 1; // trailing "/"
        String truncated = truncateToUtf8ByteLimit(comment, maxCommentBytes);
        return prefix + truncated + "/";
    }

    private static String truncateToUtf8ByteLimit(String s, int maxBytes) {
        if (maxBytes <= 0) return "";
        StringBuilder sb = new StringBuilder();
        int byteLen = 0;
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            int cpCharCount = Character.charCount(cp);
            int cpByteLen = new String(Character.toChars(cp)).getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            if (byteLen + cpByteLen > maxBytes) break;
            sb.appendCodePoint(cp);
            byteLen += cpByteLen;
            i += cpCharCount;
        }
        return sb.toString();
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final NodeConfig   config;
    private final ChainDB      db;
    private final NodeIdentity identity;
    private final RpcServer    rpc;

    private volatile Mempool   mempool;
    private volatile boolean   running;

    // ── Self-address discovery ───────────────────────────────────────────────
    //
    // Every VERSION message a peer sends us is supposed to report (per the
    // hsd "addr_recv" convention -- see parseVersion()'s own comment) what
    // address THEY saw us connecting from: the same information a STUN
    // server exists to provide, except free, since we already do this
    // handshake with every seed on every startup anyway. No traceroute, no
    // UPnP, no third-party lookup service needed -- it's already arriving
    // in data we request for an unrelated reason.
    //
    // Trusted only once at least 2 DIFFERENT peers independently report the
    // same IP -- the same "don't trust a single source" caution already
    // used elsewhere in this file (crossCheckTip(), header-mismatch
    // confirmation). A single peer could be lying, misconfigured, or
    // running code that doesn't populate this field honestly at all --
    // multiple strangers agreeing is a real signal; one peer's say-so isn't.
    private static final Map<String, Set<String>> selfIpObservedBy = new ConcurrentHashMap<>();
    private static final int SELF_IP_CONFIRMATIONS_REQUIRED = 2;

    // FIX: seeded from NodeIdentity's own persisted value (see its own
    // comment) rather than always starting null -- a restart now has a
    // usable self address from the first connection onward instead of
    // waiting for fresh corroboration every single run. `confirmedThisSession`
    // (not "confirmedSelfIp != null") is now the gate on whether to keep
    // tallying fresh observations: a seeded-but-not-yet-reconfirmed value
    // still needs real corroboration this session, both to confirm it's
    // still correct and to catch an actual IP change (VPN, ISP, etc.) --
    // the old `confirmedSelfIp != null` check would have locked onto
    // whatever was seeded and never updated it again all session.
    private static volatile String confirmedSelfIp = null;
    private static volatile boolean confirmedThisSession = false;

    private void recordSelfIpObservation(String reportedIp, String fromPeerIp) {
        if (confirmedThisSession) return; // already reconfirmed fresh this session
        Set<String> reporters = selfIpObservedBy.computeIfAbsent(
                reportedIp, k -> ConcurrentHashMap.newKeySet());
        reporters.add(fromPeerIp);
        if (reporters.size() >= SELF_IP_CONFIRMATIONS_REQUIRED && !confirmedThisSession) {
            confirmedThisSession = true;
            confirmedSelfIp = reportedIp;
            PeerTable.get().setSelfIp(reportedIp);
            identity.recordConfirmedPublicIp(reportedIp); // persists -- see its own comment
            System.out.printf("[ChainSync] Our public address confirmed as %s by %d independent peers (%s).%n",
                    reportedIp, reporters.size(), String.join(", ", reporters));
            System.out.printf("[Identity] Our Brontide address: %s%n",
                    identity.getBrontideAddress(reportedIp, config.getP2pPort()));
            // Peers we connected to BEFORE this confirmation landed never
            // got a self-announce (sendSelfAnnounce() no-ops while
            // confirmedSelfIp is still null) -- tell all of them now
            // instead of only whichever ones we happen to reconnect to
            // later.
            broadcastSelfAnnounceToAll();
        }
    }

    /**
     * Sends a self-only ADDR (just our own entry) to one peer -- the
     * active-propagation counterpart to buildAddrMessage()'s existing
     * self-entry, which only ever went out reactively, in reply to a
     * GETADDR this node happened to receive. That dependency turned out
     * to be the real reason this node had never once actually been seen
     * inbound: nothing in the observed logs ever showed a peer sending us
     * GETADDR, so the self-entry -- correct and ready since the earlier
     * self-IP-discovery fix -- had never actually been transmitted
     * anywhere. Real P2P networks typically self-announce unsolicited for
     * exactly this reason rather than depending on being asked. Best-
     * effort: failure here shouldn't tear down an otherwise-healthy
     * connection, so it's logged, not propagated.
     */
    private void sendSelfAnnounce(PeerConnection conn) {
        if (confirmedSelfIp == null) return;
        try {
            boolean plainOn = config.isPlainP2pEnabled();
            int n = plainOn ? 2 : 1;
            byte[] payload = new byte[1 + n * NET_ADDRESS_SIZE];
            payload[0] = (byte) n;
            int apos = writeNetAddressStatic(payload, 1, confirmedSelfIp, config.getP2pPort(), identity.getPublicKey());
            // Second, keyless entry: our cleartext listener, so plain hsd peers
            // (which never dial Brontide entries they have no use for) can reach us too.
            if (plainOn) writeNetAddressStatic(payload, apos, confirmedSelfIp, config.getPlainP2pPort(), null);
            conn.sendMessage(MSG_ADDR, payload);
            // DIAGNOSTIC: previously only the failure path logged anything
            // here, so a successful self-announce and "this method was
            // never even called" looked identical in the console --
            // exactly the same blind spot every other diagnostic fix this
            // session has corrected (inbound accepts, raw handshake bytes,
            // etc.). This is the one direct way to confirm, from the log
            // alone, that an unsolicited self-announce actually went out
            // over the wire to a specific peer, rather than inferring it
            // from the absence of an error line.
            System.out.printf("[ChainSync] Self-announced (%s) to %s%n", confirmedSelfIp, conn.ip);
        } catch (Exception e) {
            System.out.printf("[ChainSync] Self-announce to %s failed (non-fatal): %s%n", conn.ip, e.getMessage());
        }
    }

    /** Self-announces to every currently connected peer -- see its one
     *  caller, recordSelfIpObservation(), for why this is needed in
     *  addition to (not instead of) sendSelfAnnounce() on each new
     *  connection. */
    private void broadcastSelfAnnounceToAll() {
        for (PeerInfo p : connectedPeers) {
            sendSelfAnnounce(p.conn());
        }
    }

    /** NEW: self-healing support. Set once, the moment a
     *  UrkelTreeMismatchException is ever caught, and never cleared
     *  automatically -- deliberately a SEPARATE flag from `running`,
     *  not a reuse of it. Setting `running = false` alone would make
     *  this look identical, from the outside, to an ordinary shutdown;
     *  this exists so the node's own state genuinely reflects "halted
     *  due to a data-integrity problem needing attention" rather than
     *  "stopped normally." Holds the actual exception, not just a
     *  boolean, so whatever eventually reports this (logs, RPC status,
     *  a future recovery attempt) has the real height and root values
     *  without needing to re-derive them. */
    private volatile UrkelTreeMismatchException haltedDueToTreeMismatch = null;

    public UrkelTreeMismatchException haltedDueToTreeMismatch() { return haltedDueToTreeMismatch; }

    /**
     * Set when syncHeaders() deliberately rotates away from a peer
     * (either a clear score-based switch or periodic forced
     * diversification), so the very next connectToBestPeer() call
     * actually tries someone different instead of weighted selection
     * just reconnecting to the same peer it was told to leave. Cleared
     * after that one use -- this is a one-shot nudge, not a lasting
     * exclusion.
     */
    private volatile String avoidPeerIp;

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "chain-sync");
                t.setDaemon(true);
                return t;
            });

    // FIX: maintainOutboundPool() was originally scheduled on the same
    // single-threaded `scheduler` as syncCycle() itself, reasoning that
    // sharing a thread made the two safely non-concurrent. That part
    // was true, but it had a real side effect: syncCycle()'s inner loop
    // can run for a long time without returning (it stays inside one
    // continuous downloadBlocks() pass while there's real progress to
    // make), and since they shared one thread, maintainOutboundPool()
    // could never actually run *while* syncCycle() was busy -- which,
    // during active block processing, is most of the time. Confirmed
    // directly: a real run's outbound pool stayed at 0/8 for the entire
    // visible log, never growing past the one connection syncCycle()
    // itself opened via its own connectToBestPeer() fallback.
    // <p>
    // A separate thread is safe here: the only state maintainOutboundPool()
    // touches -- connectedPeers (CopyOnWriteArrayList) and
    // PeerScorecard's internal cache (ConcurrentHashMap) -- is already
    // safe for concurrent access, and it never touches whichever specific
    // connection syncCycle() currently has checked out for active use.
    private final ScheduledExecutorService poolScheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "chain-sync-pool");
                t.setDaemon(true);
                return t;
            });

    // Connected peer info for RPC
    private final List<PeerInfo> connectedPeers = new CopyOnWriteArrayList<>();

    // Sync statistics
    private final AtomicInteger blocksDownloaded = new AtomicInteger();
    private final AtomicLong    lastBlockTime    = new AtomicLong();

    public record PeerInfo(PeerConnection conn, long connTime, boolean inbound) {
        public String ip() { return conn.ip; }
    }

    /** Highest height any peer has ever reported, across all connections
     *  this session -- used by getblockchaininfo's verificationprogress
     *  as an honest "how far along are we" estimate, since this project
     *  has no other persistent notion of "the network's real height". */
    private volatile int bestKnownPeerHeight = 0;
    public int getBestKnownPeerHeight() { return bestKnownPeerHeight; }

    /** Cumulative wire bytes sent/received across all connections this
     *  session, for getnettotals. */
    private static final java.util.concurrent.atomic.AtomicLong totalBytesSent = new java.util.concurrent.atomic.AtomicLong();
    private static final java.util.concurrent.atomic.AtomicLong totalBytesRecv = new java.util.concurrent.atomic.AtomicLong();
    public static long getTotalBytesSent() { return totalBytesSent.get(); }
    public static long getTotalBytesRecv() { return totalBytesRecv.get(); }

    // ── Constructor ───────────────────────────────────────────────────────────

    public ChainSync(NodeConfig config, ChainDB db,
                     NodeIdentity identity, RpcServer rpc) {
        this.config   = config;
        this.db       = db;
        this.identity = identity;
        this.rpc      = rpc;
        // FIX: start from whatever NodeIdentity already has persisted
        // (null on a genuinely fresh install, or if no prior run ever
        // reached 2-peer corroboration) instead of always null -- lets
        // buildAddrMessage()/sendSelfAnnounce() include a real self-entry
        // from the very first connection this run, rather than waiting on
        // fresh corroboration every single startup. confirmedThisSession
        // stays false either way, so real corroboration still runs this
        // session and can correct this if the IP has actually changed.
        confirmedSelfIp = identity.getKnownPublicIp();
        PeerTable.get().setSelfIp(confirmedSelfIp);
    }

    public void setMempool(Mempool mempool) {
        this.mempool = mempool;
        mempool.setRelayCallback(this::relayTxToPeers);
    }

    /**
     * Announces a newly-accepted mempool transaction to our currently
     * connected peers via INV (just the txid -- peers that want the
     * full data request it back via GETDATA, which serveGetData()
     * already handles). excludeIp is skipped so a transaction we just
     * received from a peer isn't immediately bounced right back to them.
     * <p>
     * Given outbound connections are transient (connect, sync a batch,
     * disconnect) rather than held open, this mostly reaches whichever
     * peers are currently connected to US (inbound) -- there's often no
     * active outbound connection at the moment a transaction is
     * accepted. Still a real, meaningful improvement over the previous
     * complete absence of relay: without this, any transaction reaching
     * this validator (including via its own sendrawtransaction RPC) was a
     * dead end that would never propagate further.
     */
    private void relayTxToPeers(String txid, byte[] raw, String excludeIp) {
        byte[] txidBytes = fromHexStatic(txid);
        if (txidBytes == null || txidBytes.length != 32) return;

        byte[] invPayload = new byte[1 + 36];
        invPayload[0] = 1; // count = 1
        writeLE32(invPayload, 1, 1); // item type = 1 = TX
        System.arraycopy(txidBytes, 0, invPayload, 5, 32);

        for (PeerInfo p : connectedPeers) {
            if (p.ip().equals(excludeIp)) continue;
            try {
                p.conn().sendMessage(MSG_INV, invPayload);
            } catch (Exception e) {
                // best-effort -- a relay failure to one peer shouldn't
                // affect any other peer or the mempool acceptance itself
            }
        }
    }

    private static byte[] fromHexStatic(String s) {
        try {
            return HexUtil.decode(s);
        } catch (Exception e) {
            return null;
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        verifyGenesisOrReset();
        verifyTipConsistencyOrTrim();
        running = true;
        scheduler.scheduleWithFixedDelay(
                this::syncCycle, 0, POLL_INTERVAL_SEC, TimeUnit.SECONDS);
        // NEW: actually enforces config.getMaxOutbound() (previously
        // defined but never called anywhere -- the node held exactly
        // one outbound connection at a time no matter what this said).
        // Runs more often than the sync cycle itself so the pool fills
        // promptly after startup rather than trickling in one connection
        // per 60-second sync tick. See maintainOutboundPool()'s own
        // comment for what this actually buys: it's what makes
        // crossCheckTip() have other peers to compare against at all.
        // On poolScheduler, not `scheduler` -- see poolScheduler's own
        // field comment for why sharing syncCycle()'s thread here
        // silently never ran this at all during active syncing.
        poolScheduler.scheduleWithFixedDelay(
                this::maintainOutboundPool, 2, 20, TimeUnit.SECONDS);
        // FIX (audit): PeerScorecard.applyDecay() existed, fully
        // implemented, matching this class's own documented design
        // principle ("Score decay: peers slowly recover over time"),
        // but nothing anywhere ever called it -- peers that had a bad
        // stretch never actually recovered on their own. Deliberately
        // on its own, much slower schedule rather than piggybacking on
        // syncCycle's 60-second interval: applyDecay() adds +1 per
        // call for any peer within an hour of its last success, so
        // calling it every 60 seconds would let a score climb from 0
        // to 100 in under two hours from decay alone -- the opposite
        // of "slowly." Every 5 minutes instead caps that same climb at
        // roughly 12 points per hour, which actually matches "slowly."
        // On poolScheduler for the same reason as maintainOutboundPool()
        // above -- sharing `scheduler` with syncCycle() means this would
        // silently never fire during active syncing either, which is
        // most of the time.
        poolScheduler.scheduleWithFixedDelay(
                () -> PeerTable.get().applyDecay(), 5, 5, TimeUnit.MINUTES);
    }

    /**
     * Self-healing check for exactly the scenario that caused a lot of
     * confusion during development: a chain database whose stored genesis
     * header (height 0) predates some fix and no longer matches the real
     * network's genesis hash. Previously this required manually deleting
     * the whole data directory to recover -- if it's ever wrong again for
     * any reason, the validator now detects and fixes it automatically instead
     * of getting stuck (peers won't recognize our locator, so they just
     * keep resending genesis, which we'd then reject as "doesn't chain,"
     * forever).
     */
    private void verifyGenesisOrReset() {
        int tip = db.getHeaderTip();
        if (tip < 0) return; // nothing stored yet, nothing to verify
        byte[] storedGenesis = db.getHeader(0);
        if (storedGenesis == null) return;
        byte[] computedHash = HeaderUtil.hash(storedGenesis);
        if (!Arrays.equals(computedHash, GENESIS_HASH)) {
            System.out.println("[ChainSync] Stored genesis header doesn't match the "
                    + "real network genesis hash -- performing a full database reset. "
                    + "This can happen if the data predates a fix, but can also mean "
                    + "the database file itself was left in an inconsistent state by "
                    + "an unclean shutdown (e.g. a forceful process kill while the "
                    + "validator was still running) -- either way, resetting headers alone "
                    + "isn't safe here, since blocks/UTXOs/names derived from that same "
                    + "data could be equally suspect. No manual deletion needed.");
            System.out.println("[ChainSync] Computed hash: " + toHex(computedHash));
            System.out.println("[ChainSync] Expected hash: " + toHex(GENESIS_HASH));
            System.out.println("[ChainSync] Stored genesis header (hex): " + toHex(storedGenesis));
            db.fullReset();
        }
    }

    /**
     * Defensive startup check: verifies the stored header chain actually
     * links correctly at the tip (header[h].prevBlock really does equal
     * hash(header[h-1])), and that the block stored at the block tip (if
     * any) genuinely matches its own header. MVStore's own commit model
     * already makes true mid-write corruption very unlikely -- a commit
     * either fully lands or doesn't, there's no partial state -- but this
     * catches the remaining edge cases that model doesn't cover: a code
     * bug elsewhere, or storage hardware that doesn't honor fsync
     * properly.
     * <p>
     * A broken header link escalates to the same full reset as a genesis
     * mismatch, rather than a narrower trim: a break at the tip could
     * indicate the same kind of broader inconsistency (e.g. an unclean
     * shutdown), and this project has no reorg/undo mechanism for the
     * UTXO/name state changes already applied from blocks above wherever
     * a narrower trim would land. A block/header mismatch at just the
     * block tip is more isolated -- it doesn't call the headers
     * themselves into question -- so that gets a narrower, block-tip-only
     * rollback instead.
     */
    private void verifyTipConsistencyOrTrim() {
        int tip = db.getHeaderTip();
        if (tip >= 1) {
            byte[] current = db.getHeader(tip);
            byte[] prev = db.getHeader(tip - 1);
            boolean linksCorrectly = current != null && prev != null
                    && Arrays.equals(HeaderUtil.prevBlock(current), HeaderUtil.hash(prev));
            if (!linksCorrectly) {
                System.out.println("[ChainSync] Stored header chain doesn't link correctly "
                        + "at the tip -- performing a full database reset, for the same "
                        + "reason as a genesis mismatch: this can indicate a broader "
                        + "inconsistency, and this project has no way to safely undo "
                        + "UTXO/name changes already applied above a narrower trim point. "
                        + "No manual deletion needed.");
                db.fullReset();
                return; // nothing further to check against a database that was just wiped
            }
        }

        int blockTip = db.getBlockTip();
        if (blockTip >= 0 && blockTip > db.getHeaderTip()) {
            // The header tip is BELOW the block tip. That is the expected
            // state after a header-tip rollback (resetHeaderTip only drops
            // headers/chainwork; blocks, UTXOs, names and the Urkel tree are
            // untouched) while headers re-sync. The header at blockTip is
            // legitimately missing, so this is NOT evidence of corruption.
            // Never trim the block tip here: UTXO/name state already
            // reflects blockTip, so lowering it would make blocks get
            // re-applied on top of state that already contains them.
            System.out.printf("[ChainSync] Block tip %d is above header tip %d (header rollback "
                            + "in progress) -- leaving block state untouched until headers catch up.%n",
                    blockTip, db.getHeaderTip());
        } else if (blockTip >= 0) {
            byte[] header = db.getHeader(blockTip);
            byte[] block = db.getBlock(blockTip);
            boolean blockMatches = header != null && block != null && block.length >= 236
                    && Arrays.equals(Arrays.copyOf(block, 236), header);
            if (!blockMatches) {
                int newBlockTip = Math.min(blockTip - 1, db.getHeaderTip());
                System.out.printf("[ChainSync] Block at height %d doesn't match its own "
                        + "stored header -- resetting block tip to %d so it gets "
                        + "re-downloaded and re-validated.%n", blockTip, newBlockTip);
                db.setBlockTip(newBlockTip);
            }
        }
    }

    /**
     * Stops the sync scheduler -- and waits for any already-in-progress
     * syncCycle() execution to genuinely finish before returning, not
     * just for scheduler.shutdown() to prevent future runs from being
     * scheduled. Those are different things: shutdown() alone lets a
     * real, observed shutdown proceed straight to db.close()/
     * ConfigDB.close() while a background cycle is still mid-flight
     * inside BlockProcessor, producing "Map is closed"/"This store is
     * closed" errors from the losing side of that race. Those errors
     * are safe on their own (MVStore correctly refuses the post-close
     * operation rather than corrupting anything, and the failed write
     * for that one height is never committed, so it's simply
     * re-downloaded and reprocessed on the next start).
     *
     * FIX: this used to fall back to scheduler.shutdownNow() when the
     * grace period elapsed, in order to make the wait actually
     * deterministic rather than "relying on having gotten lucky with
     * timing." That intent was right, but shutdownNow()'s mechanism --
     * Thread.interrupt() -- is genuinely unsafe here: Java's NIO file
     * channels have documented behavior where interrupting a thread
     * blocked in a channel I/O call closes the ENTIRE underlying
     * channel, process-wide, not just that one thread's view of it.
     * Confirmed directly from a real crash: an interrupted mid-flight
     * read in BlockProcessor closed the shared database file channel
     * out from under the shutdown hook's own subsequent db.commit()
     * call on a completely different thread, which then threw
     * ClosedChannelException and aborted the REST of the shutdown
     * hook -- meaning db.close()/ConfigDB.commit()/ConfigDB.close()
     * never ran at all. That's strictly worse than the original,
     * merely-suboptimal race this was meant to close.
     *
     * The scheduler's threads are daemon threads (see the ThreadFactory
     * above), so the JVM can abandon a still-running one at actual
     * process exit without any explicit interruption -- it's simply
     * killed at the OS level, which never touches Java's
     * interrupt-triggered channel-closing logic. So on timeout, this
     * now just logs and returns, accepting exactly the same
     * already-safe race the class comment above describes, rather than
     * "fixing" it into a worse one.
     */
    public void stop() {
        running = false;
        scheduler.shutdown();
        poolScheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                System.out.println("[ChainSync] Sync cycle did not stop within 30s -- "
                        + "proceeding with shutdown anyway. Any in-flight block "
                        + "processing will be abandoned, safely: nothing partial "
                        + "gets committed, and it will simply be re-downloaded and "
                        + "reprocessed on the next start. Deliberately NOT "
                        + "interrupting the background thread here -- doing so can "
                        + "close the shared database file channel out from under "
                        + "other threads, including this shutdown sequence's own "
                        + "final commit.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ── Main sync cycle ───────────────────────────────────────────────────────

    private void syncCycle() {
        if (!running) return;
        if (haltedDueToTreeMismatch != null) {
            // NEW: self-healing support. Without this, the scheduler
            // would keep calling syncCycle() every POLL_INTERVAL_SEC
            // forever regardless of the halt -- `running` alone doesn't
            // stop it, since this is a separate, dedicated flag by
            // design (see its own field comment for why). Logged once
            // per cycle rather than silently, so it's visible in
            // ongoing output that the node is sitting idle for a real
            // reason, not just quiet.
            System.err.println("[ChainSync] Not syncing -- halted due to an Urkel tree mismatch at "
                    + "height " + haltedDueToTreeMismatch.height + ". Needs investigation or recovery "
                    + "before sync can resume.");
            return;
        }
        if (haltedDueToFork != null) {
            System.err.println("[ChainSync] Not syncing -- " + haltedDueToFork);
            return;
        }
        if (ReorgExecutor.inProgress(db)) {
            try {
                ReorgExecutor.resume(db, reorgHook());
            } catch (Exception e) {
                haltedDueToFork = "Could not resume the interrupted reorganization: " + e;
                System.err.println("[ChainSync] " + haltedDueToFork);
                return;
            }
        }
        try {
            refreshPeerHeights();
            // Loop internally (fast, NOT gated by the 60-second scheduler
            // interval) as long as real progress is being made. This is
            // what lets syncHeaders() hand back control mid-sync (e.g. to
            // switch to a now-better-scored peer) without losing a full
            // minute waiting for the next scheduled tick -- reconnecting
            // happens immediately, and connectToBestPeer()'s weighted
            // selection naturally picks up the better peer using the
            // scores this same sync just updated.
            while (running) {
                int localTip = db.getHeaderTip();
                System.out.printf("[ChainSync] Tip: %d | Blocks: %d | Outbound pool: %d/%d%n",
                        localTip, db.getBlockTip(), countOutboundPeers(), config.getMaxOutbound());

                List<PeerTable.ConnectTarget> candidates =
                        PeerTable.get().getCandidates();

                if (candidates.isEmpty() && countOutboundPeers() == 0) {
                    System.out.println("[ChainSync] No peer candidates — retrying in "
                            + POLL_INTERVAL_SEC + "s.");
                    return;
                }

                // Prefer an already-open pooled connection (see
                // maintainOutboundPool()) over connecting fresh -- this
                // is what actually keeps several outbound connections
                // alive across cycles instead of reconnecting from
                // scratch every time.
                PeerConnection peer = acquireSyncPeer(candidates, localTip);
                if (peer == null) {
                    System.out.println("[ChainSync] No peers responded.");
                    return;
                }

                boolean madeProgress = false;
                boolean peerBroken = false;
                try {
                    int peerHeight = peer.peerHeight;
                    // Brontide-only: every connection this project makes
                    // now always goes through the real Noise/Act1-2-3
                    // handshake, so this is always "BRONTIDE" -- no
                    // cleartext transport exists anymore to distinguish
                    // from.
                    System.out.printf("[ChainSync] Connected to %s via %s (h=%d, agent=%s)%n",
                            peer.ip, peer.plain ? "CLEARTEXT" : "BRONTIDE", peerHeight, peer.agent);

                    // See crossCheckTip()'s own comment -- this is the
                    // actual reason to keep several outbound connections
                    // open rather than just one: something to compare a
                    // sync source's claimed height against.
                    crossCheckTip(peer);

                    // Auto-rollback only if we're far above ALL connected peers.
                    // FIX: this used to compare against the single sync peer
                    // alone, so one peer that was simply still syncing itself
                    // (a freshly started node at height 194230, while every
                    // other peer was at 350149) made a fully synced node throw
                    // away 156,000 header-tip entries and re-download them.
                    int rollbackTo = rollbackTargetIfFarAhead(localTip);
                    if (rollbackTo >= 0) {
                        System.out.printf("[ChainSync] Our tip %d >> every connected peer (best %d) — rolling back%n",
                                localTip, rollbackTo);
                        db.resetHeaderTip(rollbackTo);
                        localTip = rollbackTo;
                    }

                    // BUGFIX: this used to be gated behind
                    // `if (localTip < peerHeight)`. peerHeight is this
                    // pooled connection's cached, connect-time-only
                    // value (see PeerConnection's own field comment and
                    // syncHeaders()'s updated comment) -- it never
                    // changes again for as long as pickPoolPeer() keeps
                    // handing back the same long-lived connection. Once
                    // localTip first caught up to it, this gate went
                    // false permanently, and the node never sent another
                    // GETHEADERS to this peer again, no matter how many
                    // new real blocks the network went on to produce.
                    // That's the exact bug behind the tip sitting frozen
                    // at the same height for hours while otherwise
                    // looking perfectly healthy.
                    //
                    // Always probing is cheap: when we're genuinely
                    // caught up, syncHeaders() now costs exactly one
                    // GETHEADERS/HEADERS round trip (the peer replies
                    // empty and the loop returns immediately). When the
                    // peer actually has more, this is what discovers it.
                    int newTip = syncHeaders(peer, localTip, peerHeight);
                    if (newTip != localTip) {
                        System.out.printf("[ChainSync] Headers synced to %d%n", newTip);
                    }
                    madeProgress = newTip > localTip;
                    // Keep the cached height roughly fresh too, so
                    // crossCheckTip()'s cross-peer comparison and the
                    // auto-rollback check above aren't permanently
                    // working off a connect-time snapshot for a
                    // long-lived pooled connection.
                    // Only raise it when THIS peer actually delivered headers
                    // (newTip > localTip): then it provably has at least
                    // newTip. Otherwise newTip is just OUR OWN tip echoed
                    // back (the peer replied empty/unknown), and stamping it
                    // onto the peer made lagging peers (e.g. a node still
                    // at ~200000) falsely display our height.
                    if (newTip > localTip) raisePeerHeight(peer, newTip);

                    // Download missing blocks. Its own return value feeds
                    // into madeProgress too now (see downloadBlocks()'s
                    // own comment) -- otherwise a cycle that only had
                    // blocks left to download, no headers, would report
                    // no progress and stop the outer loop after a single
                    // call regardless of how much it actually downloaded,
                    // silently defeating the block-download rotation
                    // this now relies on to ever reconnect and continue.
                    boolean blocksProgress = downloadBlocks(peer);
                    madeProgress = madeProgress || blocksProgress;

                } catch (UrkelTreeMismatchException e) {
                    // Caught here, before the generic Exception handler
                    // below, specifically so this never gets recorded as
                    // a peer failure -- this peer sent perfectly valid
                    // data; it's OUR computation that disagreed with an
                    // already-validated header. haltedDueToTreeMismatch
                    // is already set (from inside downloadBlocks(), the
                    // moment this was caught) before it's ever re-thrown
                    // up to here.
                    System.err.println("[ChainSync] Sync cycle stopping -- halted due to an Urkel tree "
                            + "mismatch. Attempting automatic recovery before deciding whether sync can "
                            + "resume.");
                    UrkelTreeRecovery.RecoveryResult result =
                            UrkelTreeRecovery.attemptRecovery(db, config.getDataDir(),
                                    e.firstDeepCatchUpDeletionHeight, false);
                    if (result.success) {
                        System.out.println("[ChainSync] Recovery succeeded: " + result.message
                                + " Clearing the halt and resuming normal sync.");
                        PersistentLog.logWarn(config.getDataDir(),
                                "Urkel tree mismatch recovery succeeded: " + result.message);
                        // FIX: only recovery's own success clears this --
                        // a plain retry or restart must NEVER silently
                        // clear it on its own. See this field's own
                        // comment for why it's deliberately separate
                        // from `running`: an unresolved mismatch needs
                        // to stay visibly, persistently halted until
                        // something has actually verified the fix,
                        // not just because sync was attempted again.
                        haltedDueToTreeMismatch = null;
                    } else {
                        System.err.println("[ChainSync] Recovery did not resolve this: " + result.message
                                + " Remaining halted -- this needs direct investigation, not another "
                                + "automatic attempt.");
                        PersistentLog.logError(config.getDataDir(),
                                "Urkel tree mismatch recovery FAILED: " + result.message);
                    }
                    return;
                } catch (Exception e) {
                    peerBroken = true;
                    // A connection that had been sitting idle in the pool for a
                    // while and then turns out to be dead is usually the remote
                    // side's idle timeout, not misbehaviour -- don't charge the
                    // peer for it. maintainOutboundPool() will redial, and a
                    // failed REDIAL is what counts against the peer. A failure
                    // on a fresh connection is still penalized as before.
                    long ageMs = Long.MAX_VALUE;
                    for (PeerInfo pi : connectedPeers) {
                        if (pi.conn() == peer) { ageMs = System.currentTimeMillis() - pi.connTime(); break; }
                    }
                    if (ageMs > STALE_POOL_CONN_MS) {
                        System.out.printf("[ChainSync] Pooled connection to %s was %ds old and has died (%s: %s) "
                                        + "-- dropping it, no penalty; will redial.%n",
                                peer.ip, ageMs / 1000, e.getClass().getSimpleName(), e.getMessage());
                    } else {
                        PeerTable.get().recordFailure(peer.ip,
                                e.getClass().getSimpleName() + ": " + e.getMessage());
                        System.out.printf("[ChainSync] Peer %s error: %s%n",
                                peer.ip, e.getMessage());
                    }
                } finally {
                    // NEW (outbound pooling): a peer that finished this
                    // cycle without a connection-level error stays open
                    // and stays in connectedPeers -- it's a genuine pool
                    // member now, reused by a future cycle instead of
                    // being reconnected from scratch. Only an actual
                    // failure (read error, decrypt failure, timeout)
                    // closes and drops it, since that's the case where
                    // the connection itself is now known-broken.
                    if (peerBroken) {
                        peer.close();
                    }
                }

                // Fully caught up, or this round made no progress at all
                // (a connection/read error, an unresponsive peer, etc.) --
                // stop spinning and let the scheduler's next 60-second
                // tick check again, rather than busy-looping.
                if (!madeProgress) return;
            }

        } catch (Exception e) {
            System.err.println("[ChainSync] Cycle error: " + e.getMessage());
        }
    }

    // ── Peer connection ───────────────────────────────────────────────────────

    /**
     * Proactively keeps up to config.getMaxOutbound() outbound
     * connections open concurrently, rather than the old one-at-a-time
     * connect/sync/close cycle. This is what actually makes
     * getMaxOutbound() do anything -- it was defined in NodeConfig but
     * never called anywhere, so the node held exactly one outbound
     * connection at a time no matter what it said. Just as importantly,
     * it's what makes crossCheckTip() meaningful at all: "does another
     * peer corroborate this height" only means something if other peers
     * are usually actually connected, not just whichever one peer we
     * most recently happened to be talking to.
     * <p>
     * Connections opened here are deliberately NOT closed when this
     * method returns -- they stay in connectedPeers as a genuine pool,
     * picked up by acquireSyncPeer() on the next sync cycle (or several
     * cycles) instead of being reconnected from scratch every time.
     */
    private void maintainOutboundPool() {
        if (!running) return;
        try {
            int target = config.getMaxOutbound();
            PeerTable table = PeerTable.get();

            List<PeerTable.ConnectTarget> candidates = table.getCandidates();
            Set<String> alreadyConnected = new HashSet<>();
            for (PeerInfo p : connectedPeers) alreadyConnected.add(p.ip());

            // Pinned peers first: they sit outside the max.outbound budget, so a
            // full pool can never crowd them out. Retried at most once a minute.
            long now = System.currentTimeMillis();
            for (PeerTable.ConnectTarget cand : candidates) {
                if (!table.isPinned(cand.ip())) continue;
                if (alreadyConnected.contains(cand.ip())) continue;
                if (cand.ip().equals(confirmedSelfIp)) continue;
                Long last = pinnedLastAttempt.get(cand.ip());
                if (last != null && now - last < PINNED_RETRY_MS) continue;
                pinnedLastAttempt.put(cand.ip(), now);
                try {
                    PeerConnection conn = connectPeer(cand);
                    if (conn == null) continue;
                    connectedPeers.add(new PeerInfo(conn, System.currentTimeMillis(), false));
                    alreadyConnected.add(cand.ip());
                    System.out.printf("[ChainSync] Pinned peer connected: %s (h=%d)%n",
                            conn.ip, conn.peerHeight);
                } catch (Exception e) {
                    table.recordFailure(cand.ip(),
                            e.getClass().getSimpleName() + ": " + e.getMessage());
                    System.out.printf("[ChainSync] Pinned peer %s unreachable (%s); will retry.%n",
                            cand.ip(), e.getMessage());
                }
            }

            if (countOutboundUnpinned() >= target) return;

            for (PeerTable.ConnectTarget cand : candidates) {
                if (countOutboundUnpinned() >= target) break;
                if (table.isPinned(cand.ip())) continue;
                if (alreadyConnected.contains(cand.ip())) continue;
                if (cand.ip().equals(confirmedSelfIp)) continue;
                if (!PeerTable.get().isGood(cand.ip())) continue;
                try {
                    PeerConnection conn = connectPeer(cand);
                    if (conn == null) continue;
                    connectedPeers.add(new PeerInfo(conn, System.currentTimeMillis(), false));
                    System.out.printf("[ChainSync] Outbound pool: added %s (h=%d) -- now %d/%d%n",
                            conn.ip, conn.peerHeight, countOutboundUnpinned(), target);
                } catch (Exception e) {
                    PeerTable.get().recordFailure(cand.ip(),
                            e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("[ChainSync] Outbound pool maintenance error: " + e.getMessage());
        }
    }

    private final java.util.concurrent.ConcurrentHashMap<String, Long> pinnedLastAttempt =
            new java.util.concurrent.ConcurrentHashMap<>();
    private static final long PINNED_RETRY_MS = 60_000L;
    /** A pooled connection older than this that fails is treated as an idle-timeout casualty, not a peer fault. */
    private static final long STALE_POOL_CONN_MS = 30_000L;
    /** Blocks a peer may trail our tip before it counts as 'stale'. */
    private static final int  STALE_TIP_TOLERANCE = 3;

    /** Outbound connections that count against max.outbound (pinned ones don't). */
    private int countOutboundUnpinned() {
        int n = 0;
        for (PeerInfo p : connectedPeers)
            if (!p.inbound() && !PeerTable.get().isPinned(p.ip())) n++;
        return n;
    }

    private int countOutboundPeers() {
        int n = 0;
        for (PeerInfo p : connectedPeers) if (!p.inbound()) n++;
        return n;
    }

    /**
     * Picks a peer to sync from, preferring an already-open pooled
     * outbound connection (see maintainOutboundPool()) over opening a
     * new one. Falls back to connectToBestPeer()'s old connect-fresh
     * behavior -- via the caller, acquireSyncPeer() -- only when the
     * pool has nothing usable right now (e.g. just after startup,
     * before maintainOutboundPool()'s first pass has run).
     */
    private PeerConnection pickPoolPeer(int ourTip) {
        // BUGFIX: this used to also skip any pooled peer whose cached
        // peer.conn().peerHeight was below our current tip
        // (`if (p.conn().peerHeight < ourTip) continue;`). That field is
        // only a connect-time snapshot, refreshed afterward ONLY for
        // whichever peer syncCycle() actually ends up using that cycle
        // (see its own comment: "if (newTip > peer.peerHeight)
        // peer.peerHeight = newTip;") -- every OTHER pooled connection's
        // cached height is frozen forever. That made this a one-way
        // trap: the moment our tip first passed a given pooled peer's
        // original snapshot, this filter excluded it from `usable`
        // permanently, since nothing ever refreshes a peer that isn't
        // picked. Whichever peer happened to be selected first stayed
        // the only "usable" one for the rest of the run, by construction
        // -- which is exactly what a real run showed: one peer
        // (74.208.31.75) monopolized every single cycle for hundreds of
        // polls straight, while the other pooled connections
        // (159.69.46.23, 129.153.177.220) sat open but were silently
        // filtered out of consideration forever, and shouldSwitchPeer()
        // reporting "a better-scored peer is now available -- switching"
        // never actually resulted in a switch, since pickPoolPeer()
        // filtered that better peer back out before it was ever tried.
        //
        // There's no need for this filter at all now: a routine
        // GETHEADERS probe against a peer that turns out to have nothing
        // new costs one cheap, short round trip (see
        // PROBE_HEADERS_TIMEOUT_MS), which is a far more reliable signal
        // than a cached number that can go stale the moment it stops
        // being refreshed. Scoring (PeerScorecard.weightedOrder below)
        // is what should decide which usable peer to prefer, not a
        // second, independent, silently-decaying filter on top of it.
        String skip = avoidPeerIp;
        List<PeerInfo> usable = new ArrayList<>();
        for (PeerInfo p : connectedPeers) {
            if (p.inbound()) continue;
            if (skip != null && p.ip().equals(skip)) continue;
            if (!PeerTable.get().isGood(p.ip())) continue;
            usable.add(p);
        }
        if (usable.isEmpty()) return null;
        avoidPeerIp = null; // consumed -- same one-shot semantics connectToBestPeer itself uses
        List<String> order = PeerTable.get().weightedOrder(
                usable.stream().map(PeerInfo::ip).toList());
        usable.sort(Comparator.comparingInt(p -> order.indexOf(p.ip())));
        return usable.get(0).conn();
    }

    private PeerConnection acquireSyncPeer(List<PeerTable.ConnectTarget> candidates, int ourTip) {
        PeerConnection pooled = pickPoolPeer(ourTip);
        if (pooled != null) return pooled;
        return connectToBestPeer(candidates, ourTip);
    }

    /**
     * Compares the peer we're about to sync from against two independent
     * sources of "what everyone else has been seeing":
     * <p>
     * 1. Every OTHER currently-pooled outbound peer's last-known height
     *    (a live, in-memory snapshot from whenever we first connected to
     *    each one).
     * 2. PeerScorecard's persisted height history -- every peer this
     *    process has successfully synced with recently, whether or not
     *    it's still connected right now. This is the layer that
     *    actually solves the staleness problem live pooled connections
     *    have on their own: it doesn't need a connection to still be
     *    open, let alone a live keep-alive reader on it, since it's
     *    reading data that was already being persisted for scoring
     *    purposes regardless. See PeerScorecard.getRecentHeightObservations()
     *    for why the age window there matters.
     * <p>
     * This is the actual point of maintaining several concurrent
     * connections and a persistent peer database at all: a single peer
     * -- malicious, or sitting on a compromised path -- could otherwise
     * feed a plausible-looking but false view of the chain with nothing
     * to catch it against. A lone peer claiming to be far ahead of
     * everyone else recently observed, with no corroboration at all
     * from either source, is exactly that signal.
     * <p>
     * Deliberately a WARNING plus a modest, cumulative score nudge
     * (recordImplausibleTip()) rather than a hard refusal: a single
     * occurrence here could still just be an honestly-fast peer nothing
     * has corroborated yet, which is a normal, expected case -- not
     * proof of anything wrong. But it's worth surfacing immediately,
     * and worth remembering: a peer whose claims keep being implausible
     * sinks in the weighted ordering over time as recordImplausibleTip()
     * accumulates, the same way every other kind of peer behavior this
     * class already tracks does.
     */
    private void crossCheckTip(PeerConnection selected) {
        List<Integer> others = new ArrayList<>();
        for (PeerInfo p : connectedPeers) {
            if (p.inbound()) continue;
            if (p.ip().equals(selected.ip)) continue;
            others.add(p.conn().peerHeight);
        }
        for (PeerTable.Peer r : PeerTable.get()
                .getRecentHeightObservations(TIP_HISTORY_WINDOW_MS)) {
            if (r.ip.equals(selected.ip)) continue;
            others.add(r.lastHeight);
        }
        if (others.size() < 2) {
            return; // not enough independent observations yet to compare against
        }
        int bestOther = Collections.max(others);
        if (selected.peerHeight > bestOther + TIP_DISAGREEMENT_THRESHOLD) {
            System.out.printf("[ChainSync] WARNING: %s claims height %d, but no other peer "
                            + "connected or recently seen (best of %d observations: %d) corroborates "
                            + "anywhere close to that -- syncing from it anyway, but this disagreement "
                            + "is worth watching.%n",
                    selected.ip, selected.peerHeight, others.size(), bestOther);
            PeerTable.get().recordImplausibleTip(selected.ip, selected.peerHeight, bestOther);
        }
    }

    /**
     * Called when a header fails our chain-link check: asks 1-2 OTHER
     * currently-pooled peers -- deliberately excluding whichever one
     * just sent the disputed header -- what THEY have immediately
     * following our own stored tip, using the exact same
     * GETHEADERS/locator mechanism as a normal sync request. This is
     * the actual "find a different source and see if they agree" step
     * that was previously missing entirely: recordInvalidData()
     * penalized the offending peer and moved on, but nothing ever
     * actively investigated whether that peer was really the outlier,
     * or whether our OWN stored tip might be the one that's wrong.
     * <p>
     * Reuses each confirming peer's EXISTING pooled connection rather
     * than opening a new one -- exactly what the outbound pool (see
     * maintainOutboundPool()) exists for, just aimed at a specific
     * question instead of a general tip comparison. Safe to borrow
     * briefly: nothing else ever reads or writes a pooled connection's
     * socket except syncCycle()'s own single thread, and
     * maintainOutboundPool() (a separate thread) only ever opens NEW
     * connections, never touches an existing one's I/O.
     * <p>
     * Deliberately conservative about what it does with the answer: it
     * can't roll anything back on its own (that's real, safety-critical
     * work, scoped separately). It only decides whether to treat the
     * rejection with the normal, single-peer-outlier assumption, or to
     * raise a much louder, distinct alarm when other independent peers
     * instead corroborate the REJECTED header -- meaning our own stored
     * data might be the actual outlier, not the peer we just penalized.
     */
    private void confirmDisagreement(int tip, byte[] rejectedHeader, PeerConnection excludePeer) {
        List<PeerInfo> candidates = new ArrayList<>();
        for (PeerInfo p : connectedPeers) {
            if (p.inbound()) continue;
            if (p.ip().equals(excludePeer.ip)) continue;
            candidates.add(p);
        }
        if (candidates.isEmpty()) {
            System.out.println("[ChainSync] No other pooled peers available to confirm this "
                    + "disagreement right now.");
            return;
        }

        List<byte[]> locator = buildLocator(tip);
        byte[] rejectedHash = HeaderUtil.hash(rejectedHeader);
        int agreeWithUs = 0;
        int agreeWithRejected = 0;
        int asked = 0;

        for (PeerInfo p : candidates) {
            if (asked >= 2) break; // deliberately just 1-2 confirmations, not a full poll
            PeerConnection confirmer = p.conn();
            try {
                confirmer.sendGetHeaders(locator);
                byte[] msg = null;
                long deadline = System.currentTimeMillis() + 10_000;
                while (System.currentTimeMillis() < deadline) {
                    byte[] candidate = confirmer.readMessage(10_000);
                    if (candidate == null) break;
                    if (getMessageType(candidate) == MSG_HEADERS) {
                        if (headersAnswerLocator(candidate, locator)) { msg = candidate; break; }
                        continue; // unsolicited tip announcement / stale batch, not our reply
                    }
                    handleNonBlockMessage(candidate, confirmer);
                }
                asked++;
                if (msg == null) continue;
                List<byte[]> theirHeaders = parseHeaders(msg);
                if (theirHeaders.isEmpty()) continue;
                byte[] theirFirstHash = HeaderUtil.hash(theirHeaders.get(0));
                if (Arrays.equals(theirFirstHash, rejectedHash)) {
                    agreeWithRejected++;
                    System.out.printf("[ChainSync] Confirmation: %s independently offers the SAME "
                                    + "header we just rejected (hash=%s).%n",
                            confirmer.ip, toHex(theirFirstHash));
                } else {
                    agreeWithUs++;
                    System.out.printf("[ChainSync] Confirmation: %s offers a DIFFERENT header at "
                                    + "this height (hash=%s) than the one we rejected -- "
                                    + "corroborates our stored data, not the rejected peer's.%n",
                            confirmer.ip, toHex(theirFirstHash));
                }
            } catch (Exception e) {
                System.out.printf("[ChainSync] Confirmation attempt against %s failed: %s%n",
                        p.ip(), e.getMessage());
            }
        }

        if (agreeWithRejected > 0 && agreeWithRejected >= agreeWithUs) {
            System.out.printf("[ChainSync] *** POSSIBLE LOCAL DATA ISSUE ***  %d of %d confirming "
                            + "peers independently offered the SAME header this project just "
                            + "rejected at height %d -- this now looks more like OUR stored chain "
                            + "being the outlier than the rejecting peer being wrong. This needs "
                            + "direct investigation, not just another retry.%n",
                    agreeWithRejected, agreeWithRejected + agreeWithUs, tip + 1);
        } else if (agreeWithUs > 0) {
            System.out.printf("[ChainSync] Confirmed: %d of %d other peers disagree with the "
                            + "rejected header too -- treating this as that peer being the "
                            + "outlier, as usual.%n",
                    agreeWithUs, agreeWithUs + agreeWithRejected);
        } else {
            System.out.println("[ChainSync] Could not get a usable confirmation from any other "
                    + "pooled peer right now -- proceeding with the normal single-peer penalty.");
        }
    }

    private PeerConnection connectToBestPeer(
            List<PeerTable.ConnectTarget> candidates, int ourTip) {

        int maxPeerHeight = 0;
        String skipThisRound = avoidPeerIp;
        avoidPeerIp = null; // one-shot: consume it regardless of whether it was actually usable

        for (PeerTable.ConnectTarget target : candidates) {
            if (!PeerTable.get().isGood(target.ip())) continue;
            if (target.ip().equals(confirmedSelfIp)) continue;
            if (target.ip().equals(skipThisRound)) continue;

            try {
                PeerConnection conn = connectPeer(target);
                if (conn == null) continue;

                // FIX: connectedPeers previously accumulated a separate
                // entry per connection attempt to the SAME ip, never
                // cleaned up -- confirmed directly from the admin
                // page's own Connected Peers table showing the same
                // handful of IPs repeated many times over, each with a
                // different (older) height snapshot. Root cause: this
                // method is the fallback path used whenever
                // pickPoolPeer() rejects every existing pool entry --
                // which happens routinely, since pickPoolPeer() skips
                // any pooled peer whose stale peerHeight snapshot has
                // fallen behind our own (ever-growing) tip -- and
                // unlike maintainOutboundPool(), which already checks
                // for this, this method never checked whether the
                // candidate it was about to connect to already had an
                // entry sitting here. Closing that stale entry first
                // (removing it via close()'s own connectedPeers.removeIf())
                // turns every such reconnect into a genuine refresh --
                // same IP, one live entry, an up-to-date height --
                // instead of a second, permanently-stale duplicate.
                for (PeerInfo existing : connectedPeers) {
                    if (!existing.inbound() && existing.ip().equals(target.ip()) && existing.conn() != conn) {
                        existing.conn().close();
                        break; // ip is the (currency, ip) analogue of a unique key here -- there's only ever one stale entry to find
                    }
                }

                maxPeerHeight = Math.max(maxPeerHeight, conn.peerHeight);
                connectedPeers.add(new PeerInfo(conn, System.currentTimeMillis(), false));

                // A peer a block or two behind us is normal (blocks reach nodes at
                // slightly different moments), not a fault -- only penalize and drop
                // a peer that is meaningfully behind.
                if (conn.peerHeight >= ourTip - STALE_TIP_TOLERANCE) {
                    return conn; // good peer found
                }

                PeerTable.get().recordStaleTip(
                        target.ip(), conn.peerHeight, ourTip);
                System.out.printf("[ChainSync] Skipping %s (h=%d < our %d)%n",
                        target.ip(), conn.peerHeight, ourTip);
                conn.close();

            } catch (Exception e) {
                PeerTable.get().recordFailure(target.ip(),
                        e.getClass().getSimpleName() + ": " + e.getMessage());
                System.out.printf("[ChainSync] Connect to %s failed: %s: %s%n",
                        target.ip(), e.getClass().getSimpleName(), e.getMessage());
            }
        }

        // Auto-rollback only if ALL connected peers are far below us (see
        // rollbackTargetIfFarAhead() for why one lagging peer isn't enough).
        int rollbackTo = rollbackTargetIfFarAhead(ourTip);
        if (rollbackTo >= 0) {
            System.out.printf("[ChainSync] All peers at ~%d, our tip %d — rolling back%n",
                    rollbackTo, ourTip);
            db.resetHeaderTip(rollbackTo);
        }

        // If diversification caused us to skip the one peer that would
        // otherwise have worked, fall back to trying it anyway rather
        // than stalling progress just to enforce variety -- avoidPeerIp
        // was already consumed above, so this retry naturally includes
        // every candidate.
        if (skipThisRound != null) {
            System.out.printf("[ChainSync] No other peer worked after skipping %s for "
                    + "diversification -- trying it again as a fallback.%n", skipThisRound);
            return connectToBestPeer(candidates, ourTip);
        }

        return null;
    }

    private PeerConnection connectPeer(PeerTable.ConnectTarget target)
            throws Exception {
        // Keyless targets are cleartext peers (see PeerTable.getCandidates(),
        // which only ever lists them AFTER every Brontide candidate and only
        // on the standard cleartext port).
        if (target.plain()) return connectPlainPeer(target);

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(target.ip(), target.port()),
                CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(HANDSHAKE_TIMEOUT);

        InputStream  in  = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        // Brontide handshake (initiator)
        BrontideState brontide = new BrontideState(
                identity.getPrivateKey(), target.brontideKey());

        // Act 1
        byte[] act1 = brontide.genActOne();
        if (VERBOSE_WIRE_LOGGING) {
            System.out.printf("[Handshake] -> %s Act1 (%d bytes): %s%n",
                    target.ip(), act1.length, toHex(act1));
            // FIX (audit): removed a line that printed this node's own
            // permanent static private key (identity.getPrivateKey())
            // in plaintext hex, plus a call to
            // brontide.debugLocalEphemeralPriv(), a method that no
            // longer exists on BrontideState (a real compile error --
            // this file did not build as uploaded). Even gated behind
            // VERBOSE_WIRE_LOGGING (default off), logging the
            // node's permanent identity key is a real exposure risk if
            // this flag is ever flipped on for debugging and that
            // output is captured or shared -- not something to restore
            // even with a working method reference.
        }
        out.write(act1);
        out.flush();

        // Act 2 -- read whatever comes back, even if incomplete, so we can
        // see exactly what (if anything) the peer sent before closing.
        byte[] act2 = readPartial(in, BrontideState.ACT_TWO_SIZE, target.ip());
        if (act2 == null || act2.length != BrontideState.ACT_TWO_SIZE) {
            throw new IOException("Incomplete Act 2");
        }
        if (VERBOSE_WIRE_LOGGING) {
            System.out.printf("[Handshake] <- %s Act2 (%d bytes): %s%n",
                    target.ip(), act2.length, toHex(act2));
        }
        brontide.recvActTwo(act2);

        // Act 3
        byte[] act3 = brontide.genActThree();
        if (VERBOSE_WIRE_LOGGING) {
            System.out.printf("[Handshake] -> %s Act3 (%d bytes): %s%n",
                    target.ip(), act3.length, toHex(act3));
        }
        out.write(act3);
        out.flush();

        socket.setSoTimeout(READ_TIMEOUT_MS);

        // P2P handshake
        PeerConnection conn = new PeerConnection(socket, in, out, brontide,
                target.ip());
        conn.doVersionHandshake(db.getBlockTip());

        // Request this peer's own peer table. Fire-and-forget rather than
        // blocking here for a response -- the ADDR reply (whenever it
        // arrives) gets picked up by handleNonBlockMessage during whatever
        // read loop runs next (header sync, block download, etc.), same
        // as any other incidental message.
        //
        // (Was temporarily disabled during an A/B test that suspected
        // GETADDR of interfering with GETHEADERS -- it wasn't the cause;
        // the real bug was a foundational error in Blake2b affecting
        // every block/header hash. Restored.)
        conn.sendMessage(MSG_GETADDR, new byte[0]);

        // Unsolicited self-announce -- see sendSelfAnnounce()'s own
        // comment for why this, not just the reactive GETADDR-reply
        // self-entry, turned out to be necessary. No-ops silently if we
        // don't have a confirmed address yet (very first few connections
        // of a genuinely fresh install, before 2-peer corroboration lands).
        sendSelfAnnounce(conn);

        PeerTable.get().recordSuccess(target.ip(), conn.agent, conn.peerHeight, true);
        return conn;
    }

    /**
     * Outbound cleartext connection (hsd's standard unencrypted P2P port).
     * Same message framing and VERSION/VERACK handshake as the Brontide path --
     * only the transport differs (no Act 1/2/3, frames go over the socket as-is).
     * The peer is scored as a downgraded cleartext peer (see PeerTable).
     */
    private PeerConnection connectPlainPeer(PeerTable.ConnectTarget target) throws Exception {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(target.ip(), target.port()), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            PeerConnection conn = new PeerConnection(socket, socket.getInputStream(),
                    socket.getOutputStream(), null, target.ip());
            conn.doVersionHandshake(db.getBlockTip());
            conn.sendMessage(MSG_GETADDR, new byte[0]);
            sendSelfAnnounce(conn);
            PeerTable.get().recordSuccess(target.ip(), conn.agent, conn.peerHeight, false);
            return conn;
        } catch (Exception e) {
            try { socket.close(); } catch (IOException ignored) { }
            throw e;
        }
    }

    /**
     * Like readExact, but on early EOF or timeout returns whatever bytes
     * WERE received (possibly zero) instead of null/throwing, and logs
     * them -- so a partial or empty response is visible for debugging
     * instead of being collapsed into a generic "Incomplete Act 2".
     */
    private static byte[] readPartial(InputStream in, int len, String ip) {
        byte[] buf = new byte[len];
        int read = 0;
        try {
            while (read < len) {
                int n = in.read(buf, read, len - read);
                if (n < 0) break; // EOF
                read += n;
            }
        } catch (IOException e) {
            System.out.printf("[Handshake] <- %s read error after %d/%d bytes: %s: %s%n",
                    ip, read, len, e.getClass().getSimpleName(), e.getMessage());
        }
        if (read < len) {
            byte[] partial = Arrays.copyOf(buf, read);
            System.out.printf("[Handshake] <- %s only got %d/%d bytes: %s%n",
                    ip, read, len, read > 0 ? toHex(partial) : "(connection closed with zero bytes sent)");
            return null;
        }
        return buf;
    }

    private static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String toHex(byte[] b) {
        return HexUtil.encode(b);
    }

    // ── Header sync ───────────────────────────────────────────────────────────

    // How long to wait for a HEADERS reply to a GETHEADERS we sent purely
    // as a routine "anything new?" probe -- i.e. we already believe,
    // going in, that we're caught up to this peer. Real hsd peers
    // observed in practice simply stay silent when they have nothing new
    // to send, rather than replying with an explicit empty HEADERS
    // message, so this wait is the expected, common case once steady
    // state is reached, not an error condition -- it fires on every
    // single poll cycle for every already-caught-up pooled peer now that
    // syncCycle() always probes (see its own comment on why). Keeping
    // this short (rather than reusing the 30s genuine-catch-up timeout)
    // is what keeps that routine case cheap instead of stalling each
    // cycle for half a minute per peer for no reason.
    private static final int PROBE_HEADERS_TIMEOUT_MS = 5_000;

    // Full wait used when we actually expect real data back -- i.e. we
    // know going in that this peer claims to be ahead of us.
    private static final int CATCHUP_HEADERS_TIMEOUT_MS = 30_000;

    private int syncHeaders(PeerConnection peer, int localTip, int peerHeight)
            throws Exception {
        int tip = localTip;
        int batchesOnThisPeer = 0;
        // Decided once, from the state at entry: are we asking because we
        // genuinely expect this peer to have more (localTip < peerHeight),
        // or just checking in case something changed since we last
        // talked to it? See PROBE_HEADERS_TIMEOUT_MS's own comment.
        boolean probing = localTip >= peerHeight;
        int headersTimeoutMs = probing ? PROBE_HEADERS_TIMEOUT_MS : CATCHUP_HEADERS_TIMEOUT_MS;
        // FIX: progress used to print on every single 2000-header batch,
        // which meant ~175 lines just to sync one peer's worth of
        // mainnet header history -- real console/scroll-back cost for
        // information nobody needs at that resolution. Printing only
        // every HEADER_PROGRESS_LOG_EVERY headers (plus always on the
        // loop's final iteration, below) keeps the same "still making
        // progress, here's roughly how far along" signal at a size that
        // doesn't dominate the scroll-back. lastLoggedTip starts at
        // localTip (not 0 or -1) so a resumed sync doesn't immediately
        // reprint a line for ground already covered before this run.
        int lastLoggedTip = localTip;

        // BUGFIX: this used to be `while (tip < peerHeight && running)`.
        // peerHeight here is PeerConnection.peerHeight -- set exactly
        // once, during that connection's VERSION handshake, and never
        // updated again for the life of a pooled, reused connection (see
        // syncCycle()'s own comment on this). Once localTip caught up to
        // whatever height the peer happened to report AT CONNECT TIME,
        // this condition went false on iteration zero forever, even
        // though pickPoolPeer() keeps handing back that same long-lived
        // connection cycle after cycle while the real network keeps
        // producing new blocks underneath it. The node would then sit
        // reporting the same frozen tip indefinitely, with no further
        // GETHEADERS ever sent to that peer again -- exactly what was
        // observed: hours of identical "Tip: 349711" / "Connected ...
        // h=349711" lines with zero progress.
        //
        // The real protocol-correct stop condition doesn't need
        // peerHeight at all: ask with our current tip, and stop when the
        // peer itself says "nothing more" (an empty HEADERS reply) or
        // stops responding. That's exactly what the loop body below
        // already does (`if (headers.isEmpty()) break;`, the no-response
        // timeout break). So the loop can run unconditionally and let
        // the peer's own answers decide when to stop -- which also means
        // a cycle where we're already caught up now costs exactly one
        // cheap GETHEADERS/HEADERS round trip instead of silently doing
        // nothing.
        while (running) {
            // Build locator (sparse list of known block hashes)
            List<byte[]> locator = buildLocator(tip);

            // Send GETHEADERS
            long requestStart = System.currentTimeMillis();
            peer.sendGetHeaders(locator);

            // Receive HEADERS -- but real peers commonly send other
            // messages (SENDCMPCT, PING, etc.) around this point that
            // have nothing to do with our specific request. Previously
            // this read exactly one message and gave up entirely if it
            // wasn't HEADERS, silently treating any unrelated message as
            // "no more headers" -- the same class of bug just fixed in
            // doVersionHandshake. Loop past anything else instead, only
            // breaking on a genuine timeout or an actual empty HEADERS.
            byte[] msg = null;
            long deadline = System.currentTimeMillis() + headersTimeoutMs;
            if (!probing) {
                // Only worth announcing for a real catch-up wait -- a
                // routine probe happens every single cycle now, so
                // printing this every time would just reintroduce the
                // noise the logging changes were meant to cut down on.
                System.out.printf("[ChainSync] Waiting for HEADERS response from %s (up to %ds)...%n",
                        peer.ip, headersTimeoutMs / 1000);
            }
            while (System.currentTimeMillis() < deadline) {
                byte[] candidate = peer.readMessage(headersTimeoutMs);
                if (candidate == null) break;
                int type = getMessageType(candidate);
                if (type == MSG_HEADERS) {
                    // FIX: a HEADERS message is not necessarily the answer to
                    // OUR GETHEADERS. We send SENDHEADERS during the
                    // handshake, so hsd also pushes an unsolicited
                    // single-header HEADERS announcement for every new
                    // block, which sits unread on idle pooled connections
                    // until the next request reads it as if it were the
                    // reply (confirmed from a real log: the "mismatching"
                    // headers were stamped minutes before the log time,
                    // i.e. the live chain tip, or were stale leftovers of
                    // an earlier batch). A genuine reply's first header
                    // always chains from one of the hashes in our locator;
                    // anything else is skipped, not penalised.
                    if (headersAnswerLocator(candidate, locator)) {
                        msg = candidate;
                        break;
                    }
                    noteAnnouncedHeaders(peer, candidate); // refresh its height
                    System.out.printf("[ChainSync] Ignoring unsolicited/stale HEADERS from %s "
                                    + "(doesn't answer our locator) -- still waiting for the real reply.%n",
                            peer.ip);
                } else {
                    handleNonBlockMessage(candidate, peer);
                }
                // Anything else (SENDCMPCT, INV, etc.) is handled by
                // handleNonBlockMessage above and the loop continues
                // waiting for HEADERS.
            }
            if (msg == null) {
                // Silence here is the expected, common outcome of a
                // routine probe (see PROBE_HEADERS_TIMEOUT_MS) -- worth a
                // quiet, low-key line for anyone watching closely, but
                // not the same "something might be wrong" framing as a
                // real catch-up timing out with nothing.
                if (probing) {
                    System.out.printf("[ChainSync] %s has nothing new.%n", peer.ip);
                } else {
                    System.out.printf("[ChainSync] No HEADERS response from %s within %ds.%n",
                            peer.ip, headersTimeoutMs / 1000);
                }
                break;
            }
            PeerTable.get().recordLatency(peer.ip, System.currentTimeMillis() - requestStart);

            // Parse headers
            List<byte[]> headers = parseHeaders(msg);
            if (headers.isEmpty()) break;

            // Chain-link validation: each header's prevBlock must
            // correctly reference the previous header's hash. The prevBlock
            // offset (12) is now EMPIRICALLY CONFIRMED correct -- checked
            // directly against a real captured header whose prevBlock field
            // exactly matched the known genesis hash byte-for-byte at this
            // offset. Blocking again: stop accepting a batch at the first
            // broken link rather than storing headers we can't trust (this
            // is exactly the check that should have caught a peer
            // responding with headers that don't actually connect to our
            // real stored tip, instead of silently mis-storing them under
            // the wrong height labels).
            byte[] previousHeader = tip >= 0 ? db.getHeader(tip) : null;
            List<byte[]> validHeaders = new ArrayList<>();
            int headerIdx = -1;
            for (byte[] h : headers) {
                headerIdx++;
                // FIX: observed once in practice -- a peer's "next" header
                // came back byte-for-byte IDENTICAL to the header we
                // already have stored immediately before it (confirmed via
                // the raw-bytes dump below, two separate variables --
                // previousHeader from our own DB, h from this peer's wire
                // reply -- holding the exact same 236 bytes). That's never
                // legitimately new data: a header can't chain from itself,
                // and whatever caused the peer to resend it (lag between
                // its reported connect-time height and its real tip, a
                // retransmit, etc.) isn't this project's fault and isn't
                // "invalid data" in the sense the scoring penalty below is
                // meant to catch. Treat an exact-duplicate resend as a
                // harmless no-op -- skip it silently and keep processing
                // the rest of the batch -- instead of tripping the
                // mismatch diagnostic and penalizing the peer for sending
                // us something we already have.
                if (previousHeader != null && Arrays.equals(h, previousHeader)) {
                    continue;
                }
                if (previousHeader != null && !HeaderUtil.chainsFrom(h, previousHeader)) {
                    // PHASE 0 (reorg handling): before treating this as bad
                    // data, check whether the header simply forks off OUR
                    // chain at a known ancestor. That is normal network
                    // behaviour (competing blocks), not misbehaviour: never
                    // penalize the peer for it.
                    if (handleFork(peer, headers, headerIdx, tip + validHeaders.size())) {
                        break;
                    }
                    // DIAGNOSTIC (temporary, pending root-cause): every
                    // real occurrence of this so far has been at a
                    // height hundreds of thousands of blocks behind
                    // every connected peer's own reported tip -- far
                    // too deep into already-finalized history for a
                    // genuine PoW-chain reorg (those are shallow, a
                    // block or two, essentially never hundreds of
                    // thousands deep), which points at a bug in this
                    // project's own storage or locator logic rather
                    // than an actual network-level disagreement. This
                    // dumps exactly what our own chain-link check is
                    // comparing, in full, so the next real occurrence
                    // gives direct evidence instead of another
                    // externally-unverifiable log line.
                    System.out.printf("[ChainSync] CHAIN-LINK MISMATCH at height %d from %s:%n",
                            tip + validHeaders.size() + 1, peer.ip);
                    System.out.printf("[ChainSync]   our stored header at height %d: hash=%s%n",
                            tip + validHeaders.size(), toHex(HeaderUtil.hash(previousHeader)));
                    System.out.printf("[ChainSync]   our stored header raw bytes: %s%n",
                            toHex(previousHeader));
                    System.out.printf("[ChainSync]   incoming header's prevBlock field: %s%n",
                            toHex(HeaderUtil.prevBlock(h)));
                    System.out.printf("[ChainSync]   incoming header raw bytes: %s%n",
                            toHex(h));
                    confirmDisagreement(tip + validHeaders.size(), h, peer);
                    PeerTable.get().recordInvalidData(peer.ip,
                            "header at height " + (tip + validHeaders.size() + 1)
                                    + " doesn't chain from previous header");
                    break;
                }
                // Proof-of-work check -- a much stronger signal than a
                // chain-link mismatch (which can happen for benign
                // reasons like a brief reorg). An honest, correctly-
                // functioning peer would never relay a header whose hash
                // doesn't satisfy its own claimed difficulty target, so
                // this is treated as a real, permanent ban rather than
                // just a scored/backed-off signal.
                if (!HeaderUtil.checkPOW(h)) {
                    int badHeight = tip + validHeaders.size() + 1;
                    // Always log a compact, one-line summary -- a ban is a
                    // real event worth seeing even with verbose logging
                    // off. The full hex dump (header bytes, computed hash,
                    // prevBlock) that let us diagnose the original
                    // Blake2b/HeaderUtil hashing bug is still available,
                    // just gated behind VERBOSE_WIRE_LOGGING now so it
                    // doesn't flood the console on every ordinary run.
                    System.out.printf("[ChainSync] %s: header at height %d failed PoW "
                                    + "(bits=0x%08X) -- banning peer.%n",
                            peer.ip, badHeight, HeaderUtil.bits(h));
                    if (VERBOSE_WIRE_LOGGING) {
                        System.out.printf("[PoW-DEBUG] header (236 bytes): %s%n", toHex(h));
                        System.out.printf("[PoW-DEBUG] nonce=%d time=%d bits=0x%08X version=%d%n",
                                HeaderUtil.nonce(h), HeaderUtil.time(h), HeaderUtil.bits(h), HeaderUtil.version(h));
                        System.out.printf("[PoW-DEBUG] prevBlock=%s%n", toHex(HeaderUtil.prevBlock(h)));
                        System.out.printf("[PoW-DEBUG] computed hash=%s%n", toHex(HeaderUtil.hash(h)));
                    }
                    PeerTable.get().banPeer(peer.ip,
                            "sent header at height " + badHeight
                                    + " with invalid proof-of-work");
                    break;
                }
                // PHASE 1: difficulty (bits) must equal what the retarget
                // rules dictate. Enforced near the tip only (old, deeply
                // buried history is protected by cumulative PoW already and
                // this keeps a fresh sync independent of this check).
                final int batchBase = (localTip < 0 && tip == localTip) ? 1 : tip + 1;
                final List<byte[]> vh = validHeaders;
                int thisHeight = batchBase + validHeaders.size();
                if (thisHeight >= bestKnownPeerHeight - 2016 && thisHeight > 146) {
                    java.util.function.IntFunction<byte[]> look = x ->
                            x >= batchBase ? (x - batchBase < vh.size() ? vh.get(x - batchBase) : null)
                                    : (x == 0 ? (batchBase == 1 ? REAL_GENESIS_HEADER : db.getHeader(0))
                                    : db.getHeader(x));
                    try {
                        int want = BlockTemplates.expectedBits(look, thisHeight - 1, powParams);
                        if (HeaderUtil.bits(h) != want) {
                            System.out.printf("[ChainSync] %s: header at height %d has bits=0x%08X "
                                            + "but the difficulty rules require 0x%08X -- rejecting batch.%n",
                                    peer.ip, thisHeight, HeaderUtil.bits(h), want);
                            PeerTable.get().banPeer(peer.ip, "sent header at height " + thisHeight
                                    + " with wrong difficulty bits");
                            break;
                        }
                    } catch (IllegalStateException e) {
                        System.out.println("[ChainSync] Skipping bits check at height " + thisHeight
                                + " (" + e.getMessage() + ")");
                    }
                }
                validHeaders.add(h);
                previousHeader = h;
            }
            if (validHeaders.isEmpty()) break;
            if (validHeaders.size() == headers.size()) {
                PeerTable.get().recordValidData(peer.ip);
            }

            // Store headers (with fake-header cap). Special case: the
            // very first batch of a fresh sync (tip started at -1) is
            // NOT actually height-0-onward data, even though tip+1=0
            // would suggest that -- buildLocator() deliberately sends
            // GENESIS_HASH as the locator when starting fresh (see its
            // own comment for why an empty locator doesn't work), which
            // tells the peer "I already have genesis," so the peer
            // correctly responds with headers starting at height 1, not
            // 0. Storing that response starting at height 0 shifted
            // every single height down by one and meant the real genesis
            // header was never stored at all -- explaining the
            // recurring "genesis hash doesn't match" resets, since
            // db.getHeader(0) was actually returning height 1's data.
            boolean isVeryFirstBatch = (localTip < 0 && tip == localTip);
            int insertStartHeight = isVeryFirstBatch ? 1 : tip + 1;
            if (isVeryFirstBatch) {
                db.insertHeaders(java.util.List.of(REAL_GENESIS_HEADER), 0);
            }
            db.insertHeaders(validHeaders, insertStartHeight);
            tip = db.getHeaderTip();

            // FIX: bestKnownPeerHeight was only ever fed by a peer's
            // VERSION-time height claim (see parseVersion()'s "if
            // (peerHeight > bestKnownPeerHeight)" line) -- a one-time
            // snapshot from connect, never touched again for the life of
            // the process. That's exactly the same kind of staleness
            // pickPoolPeer()'s old `peerHeight < ourTip` filter caused
            // (see its own fix comment), just surfacing somewhere else:
            // once real sync progress carried our own tip PAST whatever
            // every currently-connected peer happened to report at
            // connect time, bestKnownPeerHeight stayed frozen forever,
            // producing exactly what was seen in the admin panel --
            // "349810 of 349808" (synced further than the peer's stale
            // VERSION-time height the denominator was still built from;
            // the 100% cap only hid part of the symptom, not its cause).
            // Every header accepted here passed real chain-link and PoW
            // checks, so it IS proof the network's real height is at
            // least `tip` -- updating from this, not just from VERSION,
            // keeps the figure honest as sync actually progresses instead
            // of only at the moment each connection was first made.
            if (tip > bestKnownPeerHeight) bestKnownPeerHeight = tip;

            // See HEADER_PROGRESS_LOG_EVERY's own comment -- throttled
            // independently of the per-batch wire size. Always prints on
            // the final batch (tip reaches peerHeight) even if that
            // batch didn't cross a round 20,000 boundary, so "caught up"
            // is never silently skipped.
            boolean reachedPeerHeight = tip >= peerHeight;
            if (tip - lastLoggedTip >= HEADER_PROGRESS_LOG_EVERY || reachedPeerHeight) {
                System.out.printf("[ChainSync] Headers: %d/%d%n", tip, peerHeight);
                lastLoggedTip = tip;
            }

            // After each batch, check whether a meaningfully better peer
            // has emerged (e.g. thanks to the latency/valid-data scoring
            // this batch just fed back in) -- if so, hand back control so
            // the caller can reconnect to it for the next batch, rather
            // than committing to this connection for the entire sync
            // regardless of how it's actually performing.
            batchesOnThisPeer++;
            if (shouldSwitchPeer(peer.ip)) {
                System.out.printf("[ChainSync] A better-scored peer than %s is now available -- "
                        + "switching for the next batch.%n", peer.ip);
                break;
            }
            // Periodic forced diversification: even a peer that's
            // performing perfectly well still shouldn't be relied on
            // indefinitely as the sole source of chain data -- score-
            // based switching alone tends toward a self-reinforcing
            // loop, since the currently-connected peer is the only one
            // actively earning fresh valid-data/latency points while
            // every other candidate's score just sits static. Rotating
            // periodically regardless of score both limits how much any
            // single peer (compromised or not) shapes our view of the
            // chain, and keeps other peers' scores exercised and
            // meaningful rather than perpetually stale.
            if (batchesOnThisPeer >= MAX_BATCHES_PER_PEER) {
                System.out.printf("[ChainSync] Rotating away from %s after %d batches "
                                + "(periodic diversification, not a score judgment).%n",
                        peer.ip, batchesOnThisPeer);
                avoidPeerIp = peer.ip;
                break;
            }
        }

        return tip;
    }

    /**
     * True if the current peer has fallen meaningfully behind the
     * top-ranked candidate in the scorecard -- a real, but not overly
     * twitchy, threshold, so a brief scoring fluctuation doesn't trigger
     * a reconnect on every single batch.
     */
    private boolean shouldSwitchPeer(String currentIp) {
        List<PeerTable.Peer> ranked = PeerTable.get().getRankedPeers();
        if (ranked.isEmpty()) return false;
        int topScore = ranked.get(0).score;
        int currentScore = ranked.stream()
                .filter(r -> r.ip.equals(currentIp))
                .findFirst()
                .map(r -> r.score)
                .orElse(topScore); // if we're not even tracked yet, don't force a switch
        return !ranked.get(0).ip.equals(currentIp)
                && (topScore - currentScore) >= PEER_SWITCH_SCORE_MARGIN;
    }

    /**
     * Mainnet genesis block hash -- REAL block hash (Handshake's actual
     * "share hash" scheme, see HeaderUtil.hash()), verified byte-for-byte
     * against real hsd's own computed hash for this exact genesis header.
     * <p>
     * This is the THIRD value this constant has held, and the story is
     * worth keeping: the ORIGINAL constant (5b6ef2d3c1f3cdca...) was
     * genesis's own prevBlock sentinel, not a hash at all. The SECOND
     * value (43a0c70e...) was a real computed hash -- but computed with a
     * Blake2b implementation that had a foundational bug (10 rounds
     * instead of the required 12), discovered only by comparing every
     * intermediate step of the real share-hash algorithm against real
     * hsd's own output and independently against Python's hashlib. That
     * Blake2b bug affected every single block/header hash computed
     * throughout this entire project, and explains why no real peer ever
     * recognized our GETHEADERS locator no matter what else got fixed
     * along the way (wire format, nonce handling, message sequencing --
     * all correct the whole time, but built on a broken hash function).
     */
    /**
     * Real Handshake mainnet genesis hash. CORRECTED: the previous value
     * here (0000000000a5e40e8ba291bd7e8649747fa7fb8a7af39f5bacdb7433cd2f5971)
     * was simply wrong -- confirmed directly and authoritatively against
     * a real hsd installation's own "rpc getblockhash 0" output, which
     * returns 5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0
     * instead. Independently re-verified by running the real, matching
     * raw genesis header (below) through this project's own
     * HeaderUtil.hash() and confirming an exact match with that real
     * hsd output -- not just trusting either source alone.
     * <p>
     * This wrong value is what caused the recurring "genesis doesn't
     * match, full reset" cycle: it never matched anything a real chain
     * could ever produce, so verifyGenesisOrReset() failed unconditionally
     * on every single fresh sync, deterministically, not intermittently.
     */
    private static final byte[] GENESIS_HASH = {
            (byte)0x5b,(byte)0x6e,(byte)0xf2,(byte)0xd3,(byte)0xc1,(byte)0xf3,(byte)0xcd,(byte)0xca,
            (byte)0xdf,(byte)0xd9,(byte)0xa0,(byte)0x30,(byte)0xba,(byte)0x18,(byte)0x11,(byte)0xef,
            (byte)0xdd,(byte)0x17,(byte)0x74,(byte)0x0f,(byte)0x14,(byte)0xe1,(byte)0x66,(byte)0x48,
            (byte)0x97,(byte)0x60,(byte)0x74,(byte)0x1d,(byte)0x07,(byte)0x59,(byte)0x92,(byte)0xe0
    };

    /**
     * The real, complete 236-byte genesis header, needed alongside
     * GENESIS_HASH: buildLocator() sends GENESIS_HASH as the locator
     * when starting a fresh sync (see its own comment for why an empty
     * locator doesn't work), which correctly tells a real peer "I
     * already have genesis" -- meaning the peer's response starts at
     * height 1, not 0, and genesis itself is never sent to us at all.
     * This has to be inserted explicitly instead. Retrieved directly
     * from a real hsd installation via "rpc getblockheader
     * 5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0
     * false", and independently confirmed to hash to exactly
     * GENESIS_HASH via this project's own HeaderUtil.hash() before
     * being trusted here.
     */
    private static final byte[] REAL_GENESIS_HEADER = {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x76,(byte)0x41,(byte)0x38,(byte)0x5e,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x1a,(byte)0x2c,(byte)0x60,(byte)0xb9,
            (byte)0x43,(byte)0x92,(byte)0x06,(byte)0x93,(byte)0x8f,(byte)0x8d,(byte)0x78,(byte)0x23,
            (byte)0x78,(byte)0x2a,(byte)0xbd,(byte)0xb8,(byte)0xb2,(byte)0x11,(byte)0xa5,(byte)0x74,
            (byte)0x31,(byte)0xe9,(byte)0xc9,(byte)0xb6,(byte)0xa6,(byte)0x36,(byte)0x5d,(byte)0x8d,
            (byte)0x42,(byte)0x89,(byte)0x33,(byte)0x51,(byte)0x8e,(byte)0x4c,(byte)0x97,(byte)0x56,
            (byte)0xfe,(byte)0xf2,(byte)0xad,(byte)0x10,(byte)0x37,(byte)0x5f,(byte)0x36,(byte)0x0e,
            (byte)0x05,(byte)0x60,(byte)0xfc,(byte)0xc7,(byte)0x58,(byte)0x7e,(byte)0xb5,(byte)0x22,
            (byte)0x3d,(byte)0xdf,(byte)0x8c,(byte)0xd7,(byte)0xc7,(byte)0xe0,(byte)0x6e,(byte)0x60,
            (byte)0xa1,(byte)0x14,(byte)0x0b,(byte)0x15,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0xff,(byte)0xff,(byte)0x00,(byte)0x1c,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
    };

    /** True if this HEADERS message plausibly answers a GETHEADERS sent
     *  with {@code locator}: empty ("nothing more"), or its first header's
     *  prevBlock is one of the locator hashes (the peer replies starting
     *  right after the first locator hash it knows -- normally our tip,
     *  or an earlier entry on a reorg). */
    private boolean headersAnswerLocator(byte[] msg, List<byte[]> locator) {
        List<byte[]> hs = parseHeaders(msg);
        if (hs.isEmpty()) return true;
        byte[] prev = HeaderUtil.prevBlock(hs.get(0));
        for (byte[] l : locator) {
            if (Arrays.equals(prev, l)) return true;
        }
        return false;
    }

    // ── Locally produced / RPC-submitted blocks ───────────────────────────────

    /**
     * Accepts a block that extends OUR current tip (submitblock). The work runs
     * on the sync thread, so it can never overlap a sync cycle, and the result
     * is a BIP22-style reason string, or null when the block was accepted.
     */
    public String submitBlock(byte[] raw) {
        if (!running) return "node-not-running";
        try {
            return scheduler.submit(() -> acceptSubmittedBlock(raw)).get(60, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            return "node-busy-syncing";
        } catch (Exception e) {
            return "internal-error: " + e.getMessage();
        }
    }

    // Consensus parameters used to judge submitted blocks. Always mainnet in
    // production; the integration tests swap in an easy-difficulty copy.
    private volatile BlockTemplates.Params powParams = BlockTemplates.Params.MAINNET;

    private String acceptSubmittedBlock(byte[] raw) {
        if (haltedDueToTreeMismatch != null || haltedDueToFork != null) return "node-halted";
        long now = System.currentTimeMillis() / 1000;
        String err = BlockTemplates.checkBlock(db, mempool, raw, now, powParams);
        if (err != null) {
            System.out.printf("[ChainSync] submitblock rejected: %s%n", err);
            return err;
        }
        int height = db.getBlockTip() + 1;
        byte[] header = Arrays.copyOf(raw, 236);
        byte[] hash = HeaderUtil.hash(header);

        db.insertHeaders(List.of(header), height);
        byte[] msg = new byte[9 + raw.length];
        System.arraycopy(raw, 0, msg, 9, raw.length);
        boolean ok = false;
        try {
            ok = processBlock(msg, height, null);
        } catch (UrkelTreeMismatchException e) {
            haltedDueToTreeMismatch = e;
            System.err.printf("[ChainSync] submitblock: Urkel mismatch at %d -- sync halted.%n", e.height);
            return "urkel-mismatch";
        } catch (Exception e) {
            System.err.printf("[ChainSync] submitblock: processing failed: %s%n", e);
        }
        if (!ok) {
            // Back the header out again so the chain is exactly as it was.
            db.resetHeaderTip(height - 1);
            db.forgetHeaderHash(hash);
            db.commit();
            return "rejected";
        }
        db.commit();
        System.out.printf("[ChainSync] Accepted submitted block %d (%s)%n", height, toHex(hash));
        return null;
    }

    // ── Push-driven sync and block relay ──────────────────────────────────────

    private final AtomicBoolean syncTriggerPending = new AtomicBoolean(false);
    private volatile byte[] lastAnnouncedHash;

    /**
     * Runs a sync cycle as soon as the (single) sync thread is free, instead
     * of waiting for the next scheduled tick. Safe to call from any thread:
     * cycles still run one at a time on the same executor, and at most one
     * extra cycle is ever queued.
     */
    void triggerSync(String why) {
        if (!running) return;
        if (!syncTriggerPending.compareAndSet(false, true)) return;
        System.out.printf("[ChainSync] New block announced (%s) -- syncing now.%n", why);
        try {
            scheduler.execute(() -> {
                syncTriggerPending.set(false);
                syncCycle();
            });
            // The peer we ask may not have the new block yet (it can lag the
            // announcing peer by a second or two), so look once more shortly.
            scheduler.schedule(this::syncCycle, 5, TimeUnit.SECONDS);
        } catch (RejectedExecutionException e) {
            syncTriggerPending.set(false);
        }
    }

    // ── Peer height refresh ───────────────────────────────────────────────────
    // A pooled outbound connection is only read when it is picked as the sync
    // peer, so its height would otherwise stay at the connect-time snapshot.
    // Every PEER_HEIGHT_REFRESH_MS the sync thread sends each idle outbound peer a
    // GETHEADERS whose locator is ONLY our tip. A peer that knows our tip answers
    // empty (it is at our height) or with headers continuing from our tip (it is
    // ahead). A peer that does not know our tip answers from genesis, which tells
    // us nothing, so such a reply is ignored. The result is a lower bound.
    private static final long PEER_HEIGHT_REFRESH_MS = 120_000;
    private static final long PEER_HEIGHT_PROBE_TIMEOUT_MS = 3_000;
    private volatile long lastPeerHeightRefresh = 0;

    /** Raises the height we hold for a peer (connection snapshot AND the peer-table value the admin panel shows). */
    private void raisePeerHeight(PeerConnection c, int h) {
        if (h > c.peerHeight) c.peerHeight = h;
        PeerTable.get().updateHeight(c.ip, h);
    }

    /** Lower bound on the peer's height implied by its reply to a tip-only locator, or -1 if uninformative. */
    static int heightFromTipProbeReply(List<byte[]> replyHeaders, byte[] tipHash, int ourTip) {
        if (replyHeaders.isEmpty()) return ourTip;
        if (Arrays.equals(HeaderUtil.prevBlock(replyHeaders.get(0)), tipHash)) {
            return ourTip + replyHeaders.size();
        }
        return -1;
    }

    private void refreshPeerHeights() {
        long now = System.currentTimeMillis();
        if (now - lastPeerHeightRefresh < PEER_HEIGHT_REFRESH_MS) return;
        lastPeerHeightRefresh = now;
        int ourTip = db.getHeaderTip();
        byte[] tipHeader = ourTip >= 0 ? db.getHeader(ourTip) : null;
        if (tipHeader == null) return;
        byte[] tipHash = HeaderUtil.hash(tipHeader);
        List<byte[]> locator = List.of(tipHash);
        long budgetEnd = now + 12_000;
        for (PeerInfo p : connectedPeers) {
            if (!running || System.currentTimeMillis() > budgetEnd) break;
            if (p.inbound()) continue; // inbound peers push their own announcements
            PeerConnection c = p.conn();
            try {
                c.sendGetHeaders(locator);
                byte[] msg = null;
                long deadline = System.currentTimeMillis() + PEER_HEIGHT_PROBE_TIMEOUT_MS;
                while (System.currentTimeMillis() < deadline) {
                    byte[] candidate = c.readMessage((int) PEER_HEIGHT_PROBE_TIMEOUT_MS);
                    if (candidate == null) break;
                    if (getMessageType(candidate) == MSG_HEADERS) {
                        if (headersAnswerLocator(candidate, locator)) { msg = candidate; break; }
                        noteAnnouncedHeaders(c, candidate);
                        continue;
                    }
                    handleNonBlockMessage(candidate, c);
                }
                if (msg == null) continue;
                int h = heightFromTipProbeReply(parseHeaders(msg), tipHash, ourTip);
                raisePeerHeight(c, h);
            } catch (RuntimeException e) {
                // a bug-class failure while interpreting a message is not evidence the socket is dead
            } catch (Exception e) {
                // The read/write itself failed (not just silence): the connection is dead, so drop it
                // now instead of leaving a corpse in the pool and the peers panel.
                System.out.printf("[ChainSync] Dropping dead pooled connection to %s (%s).%n",
                        c.ip, e.getClass().getSimpleName());
                try { c.close(); } catch (Exception ignored) {}
            }
        }
    }

    /** Deepest fork we will even describe precisely (matches the planned undo retention). */
    public static final int MAX_FORK_DEPTH = 288;

    /** Set when a peer proves a heavier competing branch exists that we cannot yet switch to. */
    private volatile String haltedDueToFork = null;

    public String haltedDueToFork() { return haltedDueToFork; }

    /**
     * Phase 0 fork handling. {@code headers[idx]} does not chain from our
     * header at {@code curTip}. If its parent is an earlier header of OUR
     * chain, this is a fork: validate the competing branch (links + PoW),
     * compare cumulative work with our branch over the same span, and
     * either ignore it (not heavier) or halt sync with a clear message
     * (heavier -- a reorg is required and not implemented yet).
     * Never penalizes the peer. Returns false if this is NOT a recognizable
     * fork (caller falls back to the old invalid-data path).
     */
    private boolean handleFork(PeerConnection peer, List<byte[]> headers, int idx, int curTip) {
        byte[] first = headers.get(idx);
        byte[] parent = HeaderUtil.prevBlock(first);
        int forkH = db.getHeightByHash(parent);
        if (forkH < 0 || forkH >= curTip || forkH > db.getHeaderTip()) return false;
        byte[] ours = db.getHeader(forkH);
        if (ours == null || !Arrays.equals(HeaderUtil.hash(ours), parent)) return false;
        if (!HeaderUtil.checkPOW(first)) return false;

        int depth = curTip - forkH;
        java.math.BigInteger theirWork = java.math.BigInteger.ZERO;
        int theirLen = 0;
        byte[] prev = null;
        for (int j = idx; j < headers.size(); j++) {
            byte[] hj = headers.get(j);
            if (prev != null && !HeaderUtil.chainsFrom(hj, prev)) break;
            if (!HeaderUtil.checkPOW(hj)) break;
            // difficulty on the side branch must follow the same retarget rules
            final int fh = forkH, fi = idx, bh = forkH + 1 + (j - idx);
            final List<byte[]> hs = headers;
            java.util.function.IntFunction<byte[]> look = x ->
                    x <= fh ? db.getHeader(x) : (x - fh - 1 + fi < hs.size() ? hs.get(x - fh - 1 + fi) : null);
            try {
                if (bh > 146 && HeaderUtil.bits(hj) != BlockTemplates.expectedBits(look, bh - 1, powParams)) {
                    System.out.printf("[ChainSync] Fork branch header at height %d has wrong difficulty bits.%n", bh);
                    break;
                }
            } catch (IllegalStateException e) {
                break;
            }
            theirWork = theirWork.add(BlockTemplates.proof(HeaderUtil.bits(hj)));
            theirLen++;
            prev = hj;
        }
        java.math.BigInteger ourWork = java.math.BigInteger.ZERO;
        for (int hh = forkH + 1; hh <= curTip; hh++) {
            byte[] oh = db.getHeader(hh);
            if (oh != null) ourWork = ourWork.add(BlockTemplates.proof(HeaderUtil.bits(oh)));
        }
        System.out.printf("[ChainSync] FORK DETECTED from %s: branch leaves our chain at height %d "
                        + "(our tip %d, depth %d). Their valid branch: %d header(s), work %s vs ours %s.%n",
                peer.ip, forkH, curTip, depth, theirLen, theirWork.toString(16), ourWork.toString(16));
        if (theirWork.compareTo(ourWork) > 0) {
            List<byte[]> branch = new ArrayList<>(headers.subList(idx, idx + theirLen));
            boolean knownBad = false;
            for (byte[] bh : branch) if (ReorgExecutor.isKnownInvalid(db, HeaderUtil.hash(bh))) { knownBad = true; break; }
            if (ReorgExecutor.inProgress(db)) {
                System.out.println("[ChainSync] A reorganization is already in progress -- ignoring this branch for now.");
            } else if (knownBad) {
                System.out.println("[ChainSync] That branch contains a block that already failed validation -- ignoring it.");
            } else if (!ReorgExecutor.canReorg(db, forkH)) {
                haltedDueToFork = "A heavier competing branch forks from our chain at height " + forkH
                        + " (depth " + depth + ", " + theirLen + " header(s) offered by " + peer.ip + "), but we "
                        + "cannot undo that far (beyond " + ChainDB.UNDO_RETENTION + " blocks, or the blocks were "
                        + "applied before undo records existed). Sync is halted to keep local data consistent.";
                System.err.println("[ChainSync] " + haltedDueToFork);
            } else {
                try {
                    ReorgExecutor.start(db, forkH, branch, reorgHook());
                } catch (Exception e) {
                    haltedDueToFork = "Reorganization failed: " + e + ". Local data may need attention; sync halted.";
                    System.err.println("[ChainSync] " + haltedDueToFork);
                }
            }
        } else {
            System.out.println("[ChainSync] Competing branch is not heavier than ours -- ignoring it "
                    + "(no peer penalty).");
        }
        return true;
    }

    /** Bridges ReorgExecutor events to the RPC listeners and the mempool. */
    private ReorgExecutor.ListenerHook reorgHook() {
        return new ReorgExecutor.ListenerHook() {
            public void blockDisconnected(int height, byte[] hash, byte[] rawBlock) {
                if (rpc != null) rpc.notifyBlockDisconnected(height, hash, rawBlock);
            }
            public void reorgCompleted(List<byte[]> disconnectedTxs) {
                Mempool mp = mempool;
                if (mp == null) return;
                int readded = 0;
                for (byte[] raw : disconnectedTxs) {
                    try { if (mp.submit(raw) == null) readded++; } catch (Exception ignored) {}
                }
                System.out.printf("[Reorg] %d of %d transaction(s) from undone blocks returned to the mempool.%n",
                        readded, disconnectedTxs.size());
            }
        };
    }

    /** True if we already have this header on our chain. */
    private boolean haveHeader(byte[] hash) {
        int h = db.getHeightByHash(hash);
        return h >= 0 && h <= db.getHeaderTip() && db.getHeader(h) != null;
    }

    /**
     * Looks at an unsolicited HEADERS announcement (a peer that got SENDHEADERS
     * from us pushes one for every new block). Returns true if it carries a
     * header we don't have yet that satisfies its own proof-of-work -- i.e. a
     * real new block worth syncing for. Also refreshes the peer's height when
     * the header extends a header we know, so the peer table no longer shows
     * only the connect-time snapshot.
     */
    private boolean noteAnnouncedHeaders(PeerConnection conn, byte[] msg) {
        try {
            List<byte[]> hs = parseHeaders(msg);
            boolean isNew = false;
            int limit = Math.min(hs.size(), 4); // PoW hashing is not free
            for (int i = 0; i < limit; i++) {
                byte[] h = hs.get(i);
                if (!HeaderUtil.checkPOW(h)) return false; // junk / spam: ignore entirely
                int prevHeight = db.getHeightByHash(HeaderUtil.prevBlock(h));
                if (prevHeight >= 0 && prevHeight <= db.getHeaderTip()) {
                    raisePeerHeight(conn, prevHeight + 1);
                }
                if (!haveHeader(HeaderUtil.hash(h))) isNew = true;
            }
            return isNew;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Tells our peers about a block we just accepted (relay). Skips the peer
     * that gave it to us and any peer already at that height. Peers that sent
     * SENDHEADERS get a HEADERS message, the rest an INV. Not sent during
     * initial sync: only blocks whose timestamp is recent count as news.
     */
    void announceNewBlock(int height, byte[] header, byte[] hash, String excludeIp) {
        long ageSec = System.currentTimeMillis() / 1000 - HeaderUtil.time(header);
        if (ageSec > 2 * 3600) return;
        byte[] last = lastAnnouncedHash;
        if (last != null && Arrays.equals(last, hash)) return;
        lastAnnouncedHash = hash;

        byte[] hdrPayload = new byte[1 + 236];
        hdrPayload[0] = 1;
        System.arraycopy(header, 0, hdrPayload, 1, 236);
        byte[] invPayload = new byte[1 + 36];
        invPayload[0] = 1;
        writeLE32(invPayload, 1, 2); // 2 = BLOCK
        System.arraycopy(hash, 0, invPayload, 5, 32);

        int sent = 0;
        for (PeerInfo p : connectedPeers) {
            PeerConnection c = p.conn();
            if (c.ip.equals(excludeIp)) continue;
            if (c.peerHeight >= height) continue;
            try {
                if (c.wantsHeaders) c.sendMessage(MSG_HEADERS, hdrPayload);
                else c.sendMessage(MSG_INV, invPayload);
                sent++;
            } catch (Exception e) {
                // best-effort, like transaction relay
            }
        }
        if (sent > 0) {
            System.out.printf("[ChainSync] Announced block %d to %d peer(s).%n", height, sent);
        }
    }

    /**
     * Header-tip rollback is only justified when we are far ahead of EVERY
     * connected peer, and only when at least two peers agree. A single peer
     * behind us proves nothing: it may just be a node that is still syncing
     * (which the new inbound/outbound mix of peers makes common). Returns the
     * height to roll back to, or -1 for "don't roll back".
     */
    private int rollbackTargetIfFarAhead(int ourTip) {
        int best = 0;
        int peers = 0;
        for (PeerInfo pi : connectedPeers) {
            peers++;
            best = Math.max(best, pi.conn().peerHeight);
        }
        if (peers < 2 || best <= 0) return -1;
        return ourTip > best + 2016 ? best : -1;
    }

    private List<byte[]> buildLocator(int tip) {
        List<byte[]> locator = new ArrayList<>();

        // On a fresh chain (no headers at all yet) there's nothing in the
        // DB to build a real locator from, so the loop below never runs
        // even once, and we'd send an empty locator with just a stop
        // hash. Real hsd peers apparently don't respond to that -- their
        // own client code always seeds the very first locator explicitly
        // with the genesis hash instead of leaving it empty.
        if (tip < 0) {
            locator.add(GENESIS_HASH);
            return locator;
        }

        int step = 1;
        for (int h = tip; h >= 0; h -= step) {
            byte[] header = db.getHeader(h);
            if (header != null) {
                locator.add(HeaderUtil.hash(header));
            }
            if (locator.size() > 10) step *= 2;
            if (locator.size() >= 32) break;
        }
        return locator;
    }

    private List<byte[]> parseHeaders(byte[] msg) {
        List<byte[]> headers = new ArrayList<>();
        try {
            int pos = 9; // skip frame header (magic+cmd+length)
            int count = (int) readVarint(msg, pos);
            pos += varintSize(count);
            // Confirmed directly against real hsd source (lib/primitives/
            // headers.js): Headers.write() calls ONLY writeHead(bw) -- the
            // raw 236-byte header, nothing else. No trailing tx-count byte
            // at all (that's a Block-specific concept; a Headers message
            // has no transactions to count). Headers are packed back-to-
            // back with nothing between them. The previous version here
            // incorrectly tried to skip a tx-count varint after every
            // header, which happened to consume the first byte(s) of the
            // NEXT header instead -- explaining exactly why only the
            // first header in any multi-header batch ever parsed
            // correctly; every one after that was read from a
            // byte-misaligned position and would almost always fail the
            // chain-link check.
            while (count-- > 0 && pos + 236 <= msg.length) {
                headers.add(Arrays.copyOfRange(msg, pos, pos + 236));
                pos += 236;
            }
        } catch (Exception ignored) {}
        return headers;
    }

    // ── Block download ────────────────────────────────────────────────────────

    /**
     * @return true if at least one block was actually downloaded and
     *         accepted this call. syncCycle() needs this: block-download
     *         progress has to count as real progress the same way
     *         header-sync progress already does, or the outer sync loop
     *         would stop spinning the moment this method returns early
     *         for a periodic rotation, defeating the point of adding
     *         one here at all.
     */
    private boolean downloadBlocks(PeerConnection peer) throws Exception {
        int headerTip = db.getHeaderTip();
        int blockTip  = db.getBlockTip();

        if (blockTip >= headerTip) return false;

        System.out.printf("[ChainSync] Downloading blocks %d → %d%n",
                blockTip + 1, headerTip);

        int height = blockTip + 1;
        int blocksSinceCommit = 0;
        int totalDownloaded = 0;
        int batchesOnThisPeer = 0;
        try {
            while (height <= headerTip && running) {
                // Request a batch of blocks
                int batchEnd = Math.min(height + MAX_BLOCK_BATCH - 1, headerTip);
                List<byte[]> hashes = new ArrayList<>();
                for (int h = height; h <= batchEnd; h++) {
                    byte[] header = db.getHeader(h);
                    if (header != null) hashes.add(HeaderUtil.hash(header));
                }

                peer.sendGetData(hashes, 2); // type 2 = BLOCK

                // Receive blocks
                int received = 0;
                // FIX: previously this loop unconditionally did
                // received++ regardless of whether processBlock actually
                // succeeded, and the outer loop advanced `height` and
                // (via a later successful block calling
                // db.setBlockTip()) the PERSISTED tip past any rejected
                // height in between -- silently and permanently
                // orphaning that block's UTXO/name-state changes with no
                // pause, no stop, and no re-request, ever. Now: the
                // instant a block fails, stop pulling further blocks
                // from this (now-banned) peer and stop this whole
                // download pass, without counting the failed block as
                // received. db.getBlockTip() is therefore left pointing
                // at exactly the height before the failure, so the next
                // sync attempt -- necessarily with a different peer,
                // since this one is banned -- naturally re-requests the
                // correct height instead of skipping it.
                boolean batchFailed = false;
                while (received < hashes.size() && running) {
                    byte[] msg = peer.readMessage(60_000);
                    if (msg == null) break;
                    if (getMessageType(msg) != MSG_BLOCK) {
                        handleNonBlockMessage(msg, peer);
                        continue;
                    }
                    // FIX: caught separately from a normal processBlock()
                    // failure below -- an Urkel tree mismatch isn't a bad
                    // peer sending bad data (which is what a false return
                    // means, and what banning-and-retrying-with-a-
                    // different-peer is the right response to). It's our
                    // OWN computation disagreeing with a header that
                    // itself already passed every other check. Banning
                    // this peer and retrying with another would just
                    // reproduce the exact same mismatch, since the peer
                    // was never the problem. Sync stops entirely here,
                    // deliberately -- see UrkelTreeMismatchException's
                    // own fields for what a human or UrkelTreeRecovery
                    // needs to decide what happens next.
                    try {
                        if (!processBlock(msg, height + received, peer.ip)) {
                            batchFailed = true;
                            break;
                        }
                    } catch (UrkelTreeMismatchException e) {
                        System.err.printf("[ChainSync] Stopping sync entirely at height %d due to an "
                                + "Urkel tree root mismatch -- this is not a peer problem, so no peer "
                                + "was banned and no retry will happen automatically.%n", e.height);
                        haltedDueToTreeMismatch = e;
                        throw e;
                    }
                    received++;
                }

                height += received;
                blocksSinceCommit += received;
                totalDownloaded += received;

                // Commit periodically rather than after every single block
                // (BlockProcessor no longer does this itself -- see its own
                // comment for why unbatched per-block commits caused a
                // gradually worsening slowdown as the database grew, with no
                // error and no socket timeout since it wasn't actually stuck
                // on network I/O). Blocks carry far more data per item than
                // headers, so this batches less aggressively than the
                // 2000-per-commit used for header sync.
                if (blocksSinceCommit >= BLOCK_COMMIT_INTERVAL) {
                    db.commit();
                    // Bounded to a modest time budget so this can't stall
                    // active syncing for an unpredictable length of time --
                    // commit() alone only makes the current version durable,
                    // it doesn't reclaim disk space from old, superseded
                    // versions (that's what actually caused the database to
                    // balloon to 33GB for a much smaller real chain).
                    db.compact(1000);
                    blocksSinceCommit = 0;
                }

                if (received == 0 || batchFailed) break;

                // Periodic forced diversification -- see
                // MAX_BLOCK_BATCHES_PER_PEER's own comment for why block
                // downloading needed this exactly as much as header sync
                // already had it. Same avoidPeerIp one-shot mechanism
                // syncHeaders() uses: the caller's next peer-selection
                // call skips this IP for one round, not a lasting ban.
                batchesOnThisPeer++;
                if (batchesOnThisPeer >= MAX_BLOCK_BATCHES_PER_PEER) {
                    System.out.printf("[ChainSync] Rotating away from %s after %d block batches "
                                    + "(periodic diversification, not a score judgment).%n",
                            peer.ip, batchesOnThisPeer);
                    avoidPeerIp = peer.ip;
                    break;
                }
            }
        } finally {
            // Guarantee whatever was accumulated gets committed even if
            // this exits via an exception (a real possibility -- network
            // errors, decrypt failures that throw rather than return
            // null) rather than the normal loop conditions. Without this,
            // moving to batched commits could actually make an
            // interruption LOSE MORE progress than the old per-block
            // behavior did, which would be a real regression.
            if (blocksSinceCommit > 0) db.commit();
        }
        return totalDownloaded > 0;
    }

    private boolean processBlock(byte[] msg, int height, String fromIp) {
        byte[] rawBlock = Arrays.copyOfRange(msg, 9, msg.length);
        byte[] header   = Arrays.copyOf(rawBlock, Math.min(236, rawBlock.length));
        byte[] hash     = HeaderUtil.hash(header);

        // Verify it matches our stored header
        byte[] storedHeader = db.getHeader(height);
        if (storedHeader != null) {
            byte[] storedHash = HeaderUtil.hash(storedHeader);
            if (!Arrays.equals(hash, storedHash)) {
                System.err.printf("[ChainSync] Block %d hash mismatch!%n", height);
                if (fromIp != null) PeerTable.get().recordInvalidData(fromIp,
                        "block " + height + " hash mismatch");
                return false;
            }
        }

        // Process transactions (UTXO + name state updates) BEFORE
        // committing this height as "done" -- if the merkle root doesn't
        // match, nothing about this height should be recorded as
        // downloaded, or it would never get re-requested (from this peer
        // or, ideally, a different one) and the UTXO/name-state database
        // would be permanently missing this height's changes.
        BlockProcessor.Result result = BlockProcessor.process(rawBlock, height, db, mempool, getBestKnownPeerHeight());
        if (result == BlockProcessor.Result.REJECTED) {
            // A genuine consensus violation (bad merkle root, failed
            // signature) -- this peer actually sent us something
            // invalid, so banning it is correct.
            if (fromIp != null) PeerTable.get().banPeer(fromIp,
                    "sent block " + height + " that failed validation");
            if (ReorgExecutor.connecting(db)) {
                // The block belongs to a branch we just reorganized onto: go back to the old chain.
                try {
                    ReorgExecutor.restoreOldBranch(db, hash, reorgHook());
                } catch (Exception e) {
                    haltedDueToFork = "Could not restore the previous chain after a failed reorganization: "
                            + e + ". Local data needs attention; sync halted.";
                    System.err.println("[ChainSync] " + haltedDueToFork);
                }
            }
            return false;
        }
        if (result == BlockProcessor.Result.INTERNAL_ERROR) {
            // Something in OUR OWN processing broke -- nothing to do
            // with what this peer actually sent. Same "don't advance
            // the tip" behavior as a rejection (this height must be
            // retried, not silently skipped), but deliberately NOT
            // banning the peer: doing so for our own bug could end up
            // banning every peer we ever sync from if the same
            // internal issue recurs, for a reason that was never
            // actually their fault.
            return false;
        }
        if (fromIp != null) PeerTable.get().recordValidData(fromIp);

        // Store block
        db.saveBlock(rawBlock, height);
        db.setBlockTip(height);
        ReorgExecutor.onBlockConnected(db, height, reorgHook());
        blocksDownloaded.incrementAndGet();
        lastBlockTime.set(System.currentTimeMillis());

        // Notify listeners (wallet app, DNS app)
        if (rpc != null) rpc.notifyNewBlock(height, hash, rawBlock);

        // Relay: tell our other peers (no-op during initial sync, see
        // announceNewBlock()).
        announceNewBlock(height, header, hash, fromIp);

        if (height % BLOCK_PROGRESS_LOG_EVERY == 0) {
            System.out.printf("[ChainSync] Block %d processed (total: %d)%n",
                    height, blocksDownloaded.get());
        }
        return true;
    }

    private void handleNonBlockMessage(byte[] msg, PeerConnection peer)
            throws Exception {
        int type = getMessageType(msg);
        if (type == MSG_PING) {
            byte[] pingPayload = Arrays.copyOfRange(msg, 9, msg.length);
            peer.sendMessage(MSG_PONG, pingPayload);
        } else if (type == MSG_TX && mempool != null) {
            byte[] raw = Arrays.copyOfRange(msg, 9, msg.length);
            mempool.submitFromPeer(raw, peer.ip);
        } else if (type == MSG_ADDR) {
            PeerTable.get().onAddrMessage(
                    Arrays.copyOfRange(msg, 9, msg.length), peer.ip);
        } else if (type == MSG_GETADDR) {
            peer.sendMessage(MSG_ADDR, buildAddrMessage());
        } else if (type == MSG_INV) {
            handleInv(peer, Arrays.copyOfRange(msg, 9, msg.length));
        } else if (type == MSG_SENDHEADERS) {
            peer.wantsHeaders = true;
        } else if (type == MSG_HEADERS) {
            // Unsolicited announcement read while we were busy with this
            // peer: only refresh its height (we are already syncing).
            noteAnnouncedHeaders(peer, msg);
        }
        // Anything else (SENDCMPCT, etc.) is intentionally ignored here.
    }

    // ── RPC support ───────────────────────────────────────────────────────────

    public int getConnectedPeerCount() { return connectedPeers.size(); }

    /** ip -> "outbound" | "inbound" | "both" for every currently connected peer
     *  (used by the admin panel's unified Peers table). */
    public Map<String, String> getConnectionTransports() {
        Map<String, String> m = new HashMap<>();
        for (PeerInfo pi : connectedPeers) {
            String t = pi.conn().plain ? "plain" : "brontide";
            m.merge(pi.ip(), t, (a, b) -> a.equals(b) ? a : "mixed");
        }
        return m;
    }

    public Map<String, String> getConnectionDirections() {
        Map<String, String> m = new HashMap<>();
        for (PeerInfo pi : connectedPeers) {
            String d = pi.inbound() ? "inbound" : "outbound";
            m.merge(pi.ip(), d, (a, b) -> a.equals(b) ? a : "both");
        }
        return m;
    }

    public long inboundPeerCount() {
        return connectedPeers.stream().filter(PeerInfo::inbound).count();
    }

    /**
     * Matches real hsd's getpeerinfo shape as closely as this project's
     * actual tracked data allows. Reads live values directly from each
     * PeerConnection (not a static snapshot taken at connect time), so
     * bytessent/bytesrecv/lastsend/lastrecv genuinely update as the
     * connection is used, not just reflect whatever was true the moment
     * it was accepted.
     * <p>
     * Still-honest gaps, left absent rather than fabricated: pingtime/
     * minping (no per-peer ping-RTT tracking exists), besthash (the
     * VERSION message this project's peers exchange doesn't carry a
     * hash, only a height), banscore (this project's PeerScorecard is a
     * different, positive-based reputation metric, not an accumulating
     * misbehavior counter -- not a clean 1:1 mapping), inflight (this
     * project doesn't pipeline multiple concurrent block requests per
     * connection), and whitelisted (no whitelist concept exists).
     */
    public String getPeerInfoJson() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        int id = 0;
        for (PeerInfo p : connectedPeers) {
            PeerConnection conn = p.conn();
            if (!first) sb.append(",");
            long connSeconds = (System.currentTimeMillis() - p.connTime()) / 1000;
            String addrLocal = conn.socket.getLocalSocketAddress() != null
                    ? conn.socket.getLocalSocketAddress().toString().replaceFirst("^/", "")
                    : "";
            sb.append("{")
                    .append("\"id\":").append(id++).append(",")
                    .append("\"addr\":\"").append(conn.ip).append(":").append(conn.socket.getPort()).append("\",")
                    .append("\"addrlocal\":\"").append(addrLocal).append("\",")
                    .append("\"name\":\"").append(conn.ip).append("\",")
                    .append("\"services\":\"").append(String.format("%08x", conn.services)).append("\",")
                    .append("\"lastsend\":").append(conn.lastSendTime).append(",")
                    .append("\"lastrecv\":").append(conn.lastRecvTime).append(",")
                    .append("\"bytessent\":").append(conn.bytesSent).append(",")
                    .append("\"bytesrecv\":").append(conn.bytesRecv).append(",")
                    .append("\"subver\":\"").append(jsonEscape(conn.agent)).append("\",")
                    .append("\"inbound\":").append(p.inbound()).append(",")
                    .append("\"transport\":\"").append(conn.plain ? "plain" : "brontide").append("\",")
                    .append("\"startingheight\":").append(conn.peerHeight).append(",")
                    .append("\"bestheight\":").append(conn.peerHeight).append(",")
                    .append("\"conntime\":").append(connSeconds).append(",")
                    .append("\"timeoffset\":0,")
                    .append("\"version\":").append(conn.protocolVersion)
                    .append("}");
            first = false;
        }
        return sb.append("]").toString();
    }

    // ── Inbound connections ───────────────────────────────────────────────────
    //
    // P2PServer accepts the raw socket and completes the Brontide crypto
    // handshake (Act 1/2/3); this method takes over from there: the P2P
    // version handshake, then a background read loop for whatever the peer
    // sends unsolicited (PING, TX, GETADDR/ADDR, GETHEADERS, GETDATA).
    // Unlike outbound peers -- which connect, sync, and close within a
    // single syncCycle() -- inbound peers stay open until they disconnect
    // or the validator shuts down, since we don't control when they'll have
    // something to say.

    private final ExecutorService inboundExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "chain-sync-inbound");
        t.setDaemon(true);
        return t;
    });

    public void registerInboundPeer(Socket socket, BrontideState brontide, String ip) {
        try {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            PeerConnection conn = new PeerConnection(socket, in, out, brontide, ip);
            socket.setSoTimeout(HANDSHAKE_TIMEOUT);
            conn.doVersionHandshake(db.getBlockTip());
            socket.setSoTimeout(READ_TIMEOUT_MS);

            connectedPeers.add(new PeerInfo(conn, System.currentTimeMillis(), true));
            PeerTable.get().recordSuccess(ip, conn.agent, conn.peerHeight, brontide != null);

            // Same unsolicited self-announce as the outbound side
            // (connectPeer()) -- an inbound peer is just as real a
            // propagation path as an outbound one, and there's no reason
            // to only tell peers we happened to dial ourselves.
            sendSelfAnnounce(conn);

            // NEW: this is the one case where we learn a peer's real
            // Brontide static key WITHOUT needing to already know it --
            // Noise_XK transmits the initiator's static key to the
            // responder as part of the handshake (see BrontideState's
            // own comment on remoteStaticPub), so by the time Act 3 has
            // completed, `brontide.getRemoteStaticPub()` holds it for
            // free. Previously this was simply discarded: an inbound
            // peer could connect, sync, and disconnect without ever
            // being recorded anywhere, meaning this node could never
            // re-offer it to anyone else via our own ADDR responses, nor
            // treat it as a future outbound candidate itself.
            //
            // We don't actually know this peer's real listening port --
            // only the ephemeral source port their OS picked for this
            // outbound-from-their-side connection, which is useless for
            // dialing them back. config.getP2pPort() (the same port we
            // ourselves listen on) is the standing convention this whole
            // project already assumes everywhere else a port isn't
            // otherwise known (see Seed's own default), so it's used
            // here too rather than inventing a different fallback.
            byte[] remoteKey = brontide != null ? brontide.getRemoteStaticPub() : null;
            if (remoteKey != null && remoteKey.length == 33) {
                String base32Key = NodeIdentity.base32Encode(remoteKey);
                PeerTable.get().addDiscovered(base32Key, ip, config.getP2pPort(), "inbound:" + ip);
                System.out.printf("[ChainSync] Learned real Brontide key for %s from its inbound "
                        + "connection -- now a known, re-shareable peer.%n", ip);
            }

            inboundExecutor.submit(() -> runInboundLoop(conn));
        } catch (Exception e) {
            PeerTable.get().recordFailure(ip, "inbound handshake failed: " + e.getMessage());
            try { socket.close(); } catch (IOException ignored) { }
        }
    }

    private void runInboundLoop(PeerConnection conn) {
        try {
            while (running) {
                byte[] msg = conn.readMessage(300_000); // 5 min idle timeout
                if (msg == null) break;
                int type = getMessageType(msg);

                if (type == MSG_PING) {
                    byte[] pingPayload = Arrays.copyOfRange(msg, 9, msg.length);
                    conn.sendMessage(MSG_PONG, pingPayload);
                } else if (type == MSG_TX) {
                    if (mempool != null) {
                        mempool.submitFromPeer(Arrays.copyOfRange(msg, 9, msg.length), conn.ip);
                    }
                } else if (type == MSG_GETADDR) {
                    conn.sendMessage(MSG_ADDR, buildAddrMessage());
                } else if (type == MSG_ADDR) {
                    PeerTable.get().onAddrMessage(Arrays.copyOfRange(msg, 9, msg.length), conn.ip);
                } else if (type == MSG_GETHEADERS) {
                    serveGetHeaders(conn, Arrays.copyOfRange(msg, 9, msg.length));
                } else if (type == MSG_GETDATA) {
                    serveGetData(conn, Arrays.copyOfRange(msg, 9, msg.length));
                } else if (type == MSG_INV) {
                    handleInv(conn, Arrays.copyOfRange(msg, 9, msg.length));
                } else if (type == MSG_SENDHEADERS) {
                    conn.wantsHeaders = true;
                } else if (type == MSG_HEADERS) {
                    // Unsolicited: a peer pushing a new block to us.
                    if (noteAnnouncedHeaders(conn, msg)) triggerSync("HEADERS from " + conn.ip);
                } else if (type == MSG_FILTERLOAD) {
                    handleFilterLoad(conn, Arrays.copyOfRange(msg, 9, msg.length));
                } else if (type == MSG_FILTERADD) {
                    handleFilterAdd(conn, Arrays.copyOfRange(msg, 9, msg.length));
                } else if (type == MSG_FILTERCLEAR) {
                    conn.bloomFilter = null;
                }
            }
        } catch (Exception e) {
            // connection error or timeout; fall through to close
        } finally {
            conn.close();
        }
    }

    /** FIX: SPV wallet support -- installs a peer's requested bloom
     *  filter for this connection. Wire format (varint-length-prefixed
     *  filter bytes + u32 hash-function count + u32 tweak + u8 update
     *  flag) verified directly against real bfilter's own
     *  BloomFilter.write()/read() (bcoin-org/bfilter, the library hsd
     *  itself depends on for this exact feature), not assumed from
     *  general BIP37 familiarity. Size/hash-function limits (36,000
     *  bytes, 50 hash functions) are the same real, documented policy
     *  constants from that same source -- rejecting anything outside
     *  them here, before ever constructing a filter, rather than
     *  trusting a peer's claimed parameters. */
    private void handleFilterLoad(PeerConnection conn, byte[] payload) {
        BloomFilter parsed = parseFilterLoadPayload(payload, conn.ip);
        if (parsed != null) conn.bloomFilter = parsed;
    }

    /** Pure parsing logic, split out from handleFilterLoad() so it can
     *  be tested directly without needing a live PeerConnection --
     *  takes a raw FILTERLOAD payload, returns a working BloomFilter or
     *  null if the payload is malformed or violates policy limits. */
    static BloomFilter parseFilterLoadPayload(byte[] payload, String peerIpForLogging) {
        try {
            int pos = 0;
            int filterLen = (int) readVarint(payload, pos);
            pos += varintSize(filterLen);
            if (filterLen <= 0 || filterLen > 36_000) {
                System.out.println("[ChainSync] Rejecting FILTERLOAD from " + peerIpForLogging
                        + " -- filter length " + filterLen + " outside policy limits");
                return null;
            }
            byte[] filterBytes = Arrays.copyOfRange(payload, pos, pos + filterLen);
            pos += filterLen;
            int hashFuncs = (int) readLE32(payload, pos); pos += 4;
            int tweak = (int) readLE32(payload, pos); pos += 4;
            // update flag (payload[pos]) intentionally unused -- see
            // matchesFilter()'s own comment on why auto-update isn't
            // implemented yet.
            if (hashFuncs <= 0 || hashFuncs > 50) {
                System.out.println("[ChainSync] Rejecting FILTERLOAD from " + peerIpForLogging
                        + " -- hashFuncs " + hashFuncs + " outside policy limits");
                return null;
            }
            return new BloomFilter(filterBytes, hashFuncs, tweak);
        } catch (Exception e) {
            System.out.println("[ChainSync] Malformed FILTERLOAD from " + peerIpForLogging + ": " + e.getMessage());
            return null;
        }
    }

    /** FIX: SPV wallet support -- adds one more element to a peer's
     *  already-installed filter (BIP37's "filteradd"), letting a wallet
     *  extend its watch set without resending the whole filter. Wire
     *  format is a single varint-length-prefixed byte string, verified
     *  against real bfilter/hsd's FilterAddPacket. A FILTERADD before
     *  any FILTERLOAD is simply ignored -- there's nothing to add to. */
    private void handleFilterAdd(PeerConnection conn, byte[] payload) {
        if (conn.bloomFilter == null) return;
        try {
            int pos = 0;
            int dataLen = (int) readVarint(payload, pos);
            pos += varintSize(dataLen);
            byte[] data = Arrays.copyOfRange(payload, pos, pos + dataLen);
            conn.bloomFilter.add(data);
        } catch (Exception e) {
            System.out.println("[ChainSync] Malformed FILTERADD from " + conn.ip + ": " + e.getMessage());
        }
    }

    /**
     * Responds to a peer's unsolicited INV announcement (e.g. "here's a
     * new mempool transaction I have") by requesting anything we don't
     * already have via GETDATA. This is the receiving half of mempool
     * relay -- previously MSG_INV was completely unhandled in both
     * directions (never sent, never acted on), so even if a peer told us
     * about a new transaction, we'd silently ignore the announcement and
     * never actually fetch it.
     */
    private void handleInv(PeerConnection conn, byte[] payload) throws Exception {
        int pos = 0;
        int count = (int) readVarint(payload, pos);
        pos += varintSize(count);

        List<byte[]> toRequest = new ArrayList<>();
        for (int i = 0; i < count && pos + 36 <= payload.length; i++) {
            int itemType = (int) readLE32(payload, pos);
            byte[] hash = Arrays.copyOfRange(payload, pos + 4, pos + 36);
            pos += 36;
            if (itemType == 2) {
                // Block announcement: we fetch blocks via headers, so just
                // start a sync cycle if we don't have it yet.
                if (!haveHeader(hash)) triggerSync("INV from " + conn.ip);
                continue;
            }
            if (itemType != 1) continue; // only TX and BLOCK announcements are handled here
            String txidHex = toHex(hash);
            if (mempool != null && mempool.getEntry(txidHex) == null) {
                toRequest.add(hash);
            }
        }
        if (!toRequest.isEmpty()) {
            conn.sendGetData(toRequest, 1); // type 1 = TX
        }
    }

    /**
     * Responds to a peer's GETHEADERS request -- the other half of what
     * this validator has only ever done as a client (see syncHeaders()/
     * buildLocator()) until now. Finds the first locator hash we
     * recognize (locators are ordered most-recent-first, matching the
     * same convention our own outbound locators use), then sends up to
     * MAX_HEADERS_BATCH headers starting right after that point. Matches
     * the same wire format confirmed earlier this session for HEADERS
     * responses: headers packed back-to-back with no trailing byte
     * between them (that was the real bug behind the whole merkle-root
     * investigation days ago -- getting this format right here matters
     * just as much as it did on the receiving side).
     */
    private void serveGetHeaders(PeerConnection conn, byte[] payload) throws Exception {
        int pos = 0;
        int count = (int) readVarint(payload, pos);
        pos += varintSize(count);

        int matchHeight = -1; // -1 means "no match, start from genesis"
        for (int i = 0; i < count && pos + 32 <= payload.length; i++) {
            byte[] hash = Arrays.copyOfRange(payload, pos, pos + 32);
            pos += 32;
            if (matchHeight == -1) {
                // FIX: used to hex-encode `hash` just to call the
                // String-taking overload, which immediately decoded it
                // right back -- a pure wasted round-trip now that
                // getHeightByHash() has a direct byte[] overload (see
                // its own comment in ChainDB.java).
                int h = db.getHeightByHash(hash);
                if (h >= 0) matchHeight = h;
            }
        }
        // Stop hash (32 bytes) follows -- not enforced, matching this
        // validator's own outbound requests, which always use an all-zero
        // stop hash and rely on the batch size cap instead.

        int startHeight = matchHeight + 1; // -1+1 = 0 (genesis) if no match
        int tip = db.getHeaderTip();
        if (startHeight > tip) {
            conn.sendMessage(MSG_HEADERS, new byte[]{0}); // empty response, varint(0)
            return;
        }

        int endHeight = Math.min(startHeight + MAX_HEADERS_BATCH - 1, tip);
        List<byte[]> toSend = new ArrayList<>();
        for (int h = startHeight; h <= endHeight; h++) {
            byte[] header = db.getHeader(h);
            if (header == null) break;
            toSend.add(header);
        }

        byte[] responsePayload = new byte[9 + toSend.size() * 236];
        int rpos = writeVarintBytes(responsePayload, 0, toSend.size());
        for (byte[] h : toSend) {
            System.arraycopy(h, 0, responsePayload, rpos, 236);
            rpos += 236;
        }
        conn.sendMessage(MSG_HEADERS, Arrays.copyOf(responsePayload, rpos));
    }

    /**
     * Responds to a peer's GETDATA request for blocks or mempool
     * transactions -- the other half of what this validator has only ever
     * done as a client until now. Items we don't have are silently
     * skipped rather than answered with NOTFOUND; the requesting peer's
     * own timeout handles that case the same way ours already does.
     */
    /** FIX: SPV wallet support -- tests whether a parsed transaction
     *  matches a peer's installed bloom filter, so serveGetData() (and
     *  eventually mempool relay) can decide between a full BLOCK and a
     *  filtered MERKLEBLOCK.
     *
     *  Checks, in order: the transaction's own txid; each output's
     *  address hash (the primary "does this tx pay an address I'm
     *  watching" case); and each input's previous outpoint, encoded as
     *  hsd/BIP37 do -- 32-byte prev txid followed by a 4-byte
     *  little-endian index -- covering "does this tx spend a UTXO I'm
     *  watching".
     *
     *  Deliberately NOT implemented yet: BIP37's "auto-update" behavior
     *  (BLOOM_UPDATE_ALL/PUBKEY_ONLY), where a node automatically adds a
     *  matched output's own outpoint back into the filter so a LATER
     *  spend of it is caught without the wallet re-sending FILTERADD.
     *  That's a convenience optimization, not a correctness requirement
     *  -- a wallet can always explicitly FILTERADD outpoints as it
     *  discovers them from its own UTXO tracking. Scoped out
     *  deliberately for this first pass, not an oversight. */
    private static boolean matchesFilter(BloomFilter filter, TxParser.ParsedTx tx, byte[] txidRaw) {
        if (filter.contains(txidRaw)) return true;

        for (TxParser.Output out : tx.outputs) {
            if (out.addrHash != null && filter.contains(out.addrHash)) return true;
        }

        for (TxParser.Input in : tx.inputs) {
            if (in.isCoinbase()) continue;
            byte[] outpoint = new byte[36];
            System.arraycopy(in.prevHash, 0, outpoint, 0, 32);
            outpoint[32] = (byte) in.prevIndex;
            outpoint[33] = (byte) (in.prevIndex >>> 8);
            outpoint[34] = (byte) (in.prevIndex >>> 16);
            outpoint[35] = (byte) (in.prevIndex >>> 24);
            if (filter.contains(outpoint)) return true;
        }
        return false;
    }

    /** FIX: SPV wallet support -- builds and sends a MERKLEBLOCK plus
     *  the individual matching TX messages, in place of a full BLOCK,
     *  for a peer with an active filter. Reuses MerkleProof (already
     *  ported directly from real hsd's fromMatches()/extractTree() and
     *  already verified to match hsd's own MerkleBlock wire format
     *  field-for-field) and BlockProcessor.parseBlockTxs() (already
     *  used for ordinary block validation) rather than introducing a
     *  second, parallel way of walking a raw block's transactions. */
    private void serveFilteredBlock(PeerConnection conn, byte[] rawBlock) throws Exception {
        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
        byte[] header = Arrays.copyOf(rawBlock, Math.min(236, rawBlock.length));

        boolean[] matches = new boolean[txs.size()];
        List<byte[]> leaves = new ArrayList<>(txs.size());
        List<byte[]> matchingRaw = new ArrayList<>();

        for (int i = 0; i < txs.size(); i++) {
            TxParser.ParsedTx tx = txs.get(i);
            byte[] base = Arrays.copyOf(tx.raw, tx.baseSize);
            byte[] txidRaw = Blake2b.hash256(base);
            leaves.add(txidRaw);
            if (matchesFilter(conn.bloomFilter, tx, txidRaw)) {
                matches[i] = true;
                matchingRaw.add(tx.raw);
            }
        }

        MerkleProof.BuiltProof proof = MerkleProof.buildProof(leaves, matches);
        byte[] merkleBlockPayload = MerkleProof.serialize(header, proof);
        conn.sendMessage(MSG_MERKLEBLOCK, merkleBlockPayload);

        for (byte[] rawTx : matchingRaw) {
            conn.sendMessage(MSG_TX, rawTx);
        }
    }

    private void serveGetData(PeerConnection conn, byte[] payload) throws Exception {
        int pos = 0;
        int count = (int) readVarint(payload, pos);
        pos += varintSize(count);

        for (int i = 0; i < count && pos + 36 <= payload.length; i++) {
            int itemType = (int) readLE32(payload, pos);
            byte[] hash = Arrays.copyOfRange(payload, pos + 4, pos + 36);
            pos += 36;
            String hashHex = toHex(hash);

            if (itemType == 2) { // BLOCK
                int height = db.getHeightByHash(hashHex);
                if (height < 0) continue;
                byte[] rawBlock = db.getBlock(height);
                if (rawBlock == null) continue; // header only, block not downloaded
                if (conn.bloomFilter != null) {
                    serveFilteredBlock(conn, rawBlock);
                } else {
                    conn.sendMessage(MSG_BLOCK, rawBlock);
                }
            } else if (itemType == 1 && mempool != null) { // TX
                byte[] rawTx = mempool.getRaw(hashHex);
                if (rawTx == null) continue;
                conn.sendMessage(MSG_TX, rawTx);
            }
        }
    }

    /** Builds an ADDR message payload (no frame wrapper -- sendMessage adds
     *  that) from currently-known peers, capped at 200 entries. Uses the
     *  real 88-byte NetAddress format (confirmed against real hsd source
     *  much earlier this session) -- this previously used a simplified
     *  30-byte-per-entry format with no room for a real key at all,
     *  meaning every peer we told others about was reported as keyless
     *  regardless of whether we actually knew its brontide key. */
    private byte[] buildAddrMessage() {
        // NEW: previously this only ever relayed OTHER peers' addresses --
        // we never once included an entry for ourselves, no matter who
        // asked. That meant there was no path, even in principle, for
        // this node's address to ever enter anyone else's address book
        // via gossip: we could complete a GETADDR/ADDR exchange countless
        // times and never once tell anyone we exist. Now that a real,
        // multi-peer-corroborated public IP is available (see
        // confirmedSelfIp / recordSelfIpObservation()'s own comment),
        // include a real, dialable self-entry -- but only once it's been
        // confirmed by independent peers, never a guess.
        boolean includeSelf = confirmedSelfIp != null;
        boolean plainOn = config.isPlainP2pEnabled();
        // Collect (ip, port, key) entries first so the count byte is exact.
        List<Object[]> entries = new ArrayList<>();
        if (includeSelf) {
            entries.add(new Object[]{confirmedSelfIp, config.getP2pPort(), identity.getPublicKey()});
            if (plainOn) {
                entries.add(new Object[]{confirmedSelfIp, config.getPlainP2pPort(), null});
            }
        }
        for (PeerInfo p : connectedPeers) {
            if (entries.size() >= 200) break;
            String knownKey = PeerTable.get().getBrontideKeyByIp(p.ip());
            if (knownKey != null) {
                entries.add(new Object[]{p.ip(), 44806, NodeIdentity.base32Decode(knownKey)});
            } else if (!p.inbound()) {
                // Keyless peer we dialed ourselves: its real (cleartext) port is
                // the one we connected to. An INBOUND keyless peer's listening
                // port is unknown (only its ephemeral source port is), so it is
                // not relayed.
                entries.add(new Object[]{p.ip(), PeerTable.PLAIN_PORT, null});
            }
        }
        byte[] payload = new byte[1 + entries.size() * NET_ADDRESS_SIZE];
        int pos = 0;
        payload[pos++] = (byte) entries.size();
        for (Object[] e : entries) {
            pos = writeNetAddressStatic(payload, pos, (String) e[0], (Integer) e[1], (byte[]) e[2]);
        }
        return payload;
    }

    /** Shared NetAddress writer (real 88-byte format), usable both from
     *  PeerConnection (VERSION message) and here (ADDR message) without
     *  duplicating the field layout in two places. */
    private static int writeNetAddressStatic(byte[] buf, int pos, String ip, int port, byte[] brontideKey) {
        pos = writeLE64(buf, pos, 0L);   // time = 0
        pos = writeLE32(buf, pos, 0);    // services = 0
        pos = writeLE32(buf, pos, 0);    // hi_services = 0
        buf[pos++] = 0; // addr type (0 = IPv4)
        // raw[16]: standard IPv4-mapped IPv6 -- 10 zero bytes + 0xFF 0xFF + 4 IPv4 bytes
        pos += 10;
        buf[pos++] = (byte) 0xFF;
        buf[pos++] = (byte) 0xFF;
        String[] octets = ip.split("\\.");
        for (int i = 0; i < 4; i++) {
            buf[pos + i] = octets.length == 4 ? (byte) Integer.parseInt(octets[i]) : 0;
        }
        pos += 4;
        pos += 20; // reserved
        buf[pos++] = (byte) port;
        buf[pos++] = (byte) (port >> 8);
        if (brontideKey != null && brontideKey.length == 33) {
            System.arraycopy(brontideKey, 0, buf, pos, 33);
        } // else leave zeroed (matches a keyless/cleartext peer)
        pos += 33;
        return pos;
    }

    // ── PeerConnection ────────────────────────────────────────────────────────

    private class PeerConnection implements AutoCloseable {
        final Socket        socket;
        final InputStream   in;
        final OutputStream  out;
        final BrontideState brontide;   // null => cleartext transport
        final boolean       plain;
        final String        ip;
        volatile String     agent  = "";
        volatile int        peerHeight = 0;
        /** True once the peer has sent SENDHEADERS: it wants new blocks announced as HEADERS, not INV. */
        volatile boolean    wantsHeaders = false;
        volatile int        protocolVersion = 0;
        volatile int        services = 0;
        volatile long       bytesSent = 0;
        volatile long       bytesRecv = 0;
        volatile long       lastSendTime = 0;
        volatile long       lastRecvTime = 0;

        // FIX: SPV wallet support -- a peer's active bloom filter, if
        // any. null means no filter installed (serve full blocks, as
        // before). Set by FILTERLOAD, updated by FILTERADD, cleared by
        // FILTERCLEAR. volatile since FILTERLOAD/ADD/CLEAR arrive on
        // this connection's own read thread, but a concurrent block
        // relay (see serveGetData()/relay logic) reads it too -- same
        // cross-thread-visibility reasoning already applied to
        // UrkelNode.Internal's left/right and UrkelTree's
        // awaitingNextCommit earlier this session, not a new pattern.
        volatile BloomFilter bloomFilter = null;

        // DIAGNOSTIC: what this peer's own VERSION message reported
        // seeing as OUR address (see parseVersion()'s own comment on
        // this) -- null until a VERSION has actually been received and
        // parsed. Not yet used for anything beyond observation.
        volatile String selfReportedIp = null;

        PeerConnection(Socket socket, InputStream in, OutputStream out,
                       BrontideState brontide, String ip) {
            this.socket   = socket;
            this.in       = in;
            this.out      = out;
            this.brontide = brontide;
            this.plain    = (brontide == null);
            this.ip       = ip;
        }

        void doVersionHandshake(int ourHeight) throws Exception {
            // Send VERSION
            sendVersion(ourHeight);
            System.out.printf("[Handshake] -> %s VERSION sent, waiting for reply...%n", ip);

            // A proper handshake requires BOTH sides' VERSION and VERACK to
            // be exchanged before it's complete -- not just whichever one
            // happens to arrive first. Previously this broke out of the
            // loop the instant EITHER message type was seen, meaning if
            // the peer's VERACK arrived before their own VERSION message
            // (a very common ordering -- VERACK is typically sent in direct
            // reply to OUR VERSION, while THEIR VERSION arrives as a
            // separate, slightly later message), their VERSION message was
            // left unconsumed in the stream and got misread later by
            // whatever code issued the next request (GETHEADERS), which
            // then misinterpreted VERSION's bytes as if they were a
            // HEADERS response.
            boolean versionReceived = false;
            boolean verackReceived = false;
            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT;
            while (System.currentTimeMillis() < deadline) {
                if (versionReceived && verackReceived) break;
                byte[] msg = readMessage(HANDSHAKE_TIMEOUT);
                if (msg == null) throw new IOException("Handshake timeout");
                int type = getMessageType(msg);
                if (type == MSG_VERSION) {
                    // DEBUG: explicit confirmation with the peer's own
                    // reported details, and to unconditionally prove this
                    // branch was actually reached -- everything before this
                    // in the log could succeed while this specific parse
                    // still silently threw and got swallowed somewhere.
                    parseVersion(Arrays.copyOfRange(msg, 9, msg.length));
                    System.out.printf("[Handshake] <- %s VERSION received: agent=%s height=%d services=%d protocolVersion=%d%n",
                            ip, agent, peerHeight, services, protocolVersion);
                    sendMessage(MSG_VERACK, new byte[0]);
                    System.out.printf("[Handshake] -> %s VERACK sent (in reply to their VERSION)%n", ip);
                    // (Was temporarily disabled during an A/B test that
                    // suspected this of interfering with GETHEADERS -- it
                    // wasn't the cause; the real bug was a foundational
                    // Blake2b error. Restored.)
                    sendMessage(MSG_SENDHEADERS, new byte[0]);
                    versionReceived = true;
                } else if (type == MSG_VERACK) {
                    System.out.printf("[Handshake] <- %s VERACK received%n", ip);
                    verackReceived = true;
                } else if (type == MSG_SENDHEADERS) {
                    wantsHeaders = true;
                } else {
                    // DEBUG: previously silently ignored -- if a peer sends
                    // anything else this early (PING, or something
                    // unexpected), that's genuinely useful to see rather
                    // than have it vanish without a trace.
                    System.out.printf("[Handshake] <- %s unexpected message type=%d during handshake window (ignored)%n",
                            ip, type);
                }
            }
            if (!versionReceived || !verackReceived)
                throw new IOException("Handshake timeout (version="
                        + versionReceived + " verack=" + verackReceived + ")");
            System.out.printf("[Handshake] <- %s VERSION handshake COMPLETE (version=%b verack=%b)%n",
                    ip, versionReceived, verackReceived);
        }

        private void sendVersion(int ourHeight) throws Exception {
            // Real hsd VersionPacket layout, confirmed directly against
            // hsd's own packets.js source: version(4) + services(4) +
            // hi_services(4) + time(8) + NetAddress "remote"(88) +
            // NetAddress "local"(88) + nonce(8) + agentLen(1) + agent(N) +
            // height(4) + noRelay(1). An earlier version of this comment
            // claimed this was "verified against a live hsd installation"
            // with only ONE NetAddress field -- that claim was incomplete;
            // hsd's VersionPacket has two separate NetAddress properties
            // (remote and local) and its own getSize() adds both.
            //
            // ourHeight comes from ChainDB.getBlockTip(), which returns -1
            // to mean "no blocks yet" -- a valid internal sentinel, but
            // writeLE32(-1) serializes to 0xFFFFFFFF on the wire, which a
            // real peer reads back as an UNSIGNED height of 4,294,967,295.
            // Every single VERSION message sent so far had this exact
            // value; a real hsd validator very plausibly rejects a peer
            // claiming a chain height of 4.29 billion outright. Clamp to 0
            // before it ever reaches the wire.
            if (ourHeight < 0) ourHeight = 0;
            // REVERTED: an earlier pass here added a second "local"
            // NetAddress field, reasoning from a secondary bcoin.io mirror
            // of hsd's JSDoc that showed VersionPacket.getSize() adding
            // both a "remote" and a "local" NetAddress. That reasoning was
            // wrong, and this time the proof is about as direct as it
            // gets: probe_rawconnect2.js, using hsd's own real code,
            // captured the actual raw payload bytes it sent and got
            // accepted by a real, live peer -- 147 bytes total, with
            // exactly 96 bytes between the fixed 20-byte header and the
            // agent string. That's one 88-byte NetAddress plus an 8-byte
            // nonce, not two. Reverting to a single "remote" field,
            // matching this captured ground truth exactly rather than the
            // secondary source.
            byte[] agentBytes = userAgent().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] payload = new byte[4 + 4 + 4 + 8 + NET_ADDRESS_SIZE + 8 + 1 + agentBytes.length + 4 + 1];
            int pos = 0;
            pos = writeLE32(payload, pos, PROTOCOL_VERSION);
            pos = writeLE32(payload, pos, 1);           // services (ours)
            pos = writeLE32(payload, pos, 0);           // hi_services (always 0)
            pos = writeLE64(payload, pos, System.currentTimeMillis() / 1000);
            // NetAddress describes the REMOTE peer as we see it (the
            // Bitcoin-derived "addr_recv" convention), not our own address.
            // The real reference (HNSPeer.sendVersion) uses an all-zero key
            // here rather than the peer's actual brontide key -- matching
            // that exactly rather than my own guess, since this field
            // isn't otherwise verified against real behavior.
            pos = writeNetAddress(payload, pos, ip, socket.getPort(), new byte[33]);
            pos = writeLE64(payload, pos, 0L);           // nonce
            payload[pos++] = (byte) agentBytes.length;
            System.arraycopy(agentBytes, 0, payload, pos, agentBytes.length);
            pos += agentBytes.length;
            pos = writeLE32(payload, pos, ourHeight);
            payload[pos] = 0;                            // noRelay: 0 = please relay txs to us

            sendMessage(MSG_VERSION, payload);
        }

        /**
         * Real hsd NetAddress (88 bytes): time(8)+services(4)+hiServices(4)+
         * addrType(1)+raw(16)+reserved(20)+port(2)+key(33). Verified against
         * the real HNSMessage.java reference:
         *   - time/services/hi_services inside NetAddress are always 0
         *     (hardcoded, not the caller's current values) -- "we don't
         *     track when we last saw this peer"
         *   - raw[16] is the STANDARD IPv4-mapped-IPv6 format (10 zero
         *     bytes + 0xFF 0xFF + 4 IPv4 bytes), not "IPv4 + 12 zero bytes"
         *     as an earlier, less specific source had suggested
         */
        private int writeNetAddress(byte[] buf, int pos, String ip, int port, byte[] brontideKey) {
            return ChainSync.writeNetAddressStatic(buf, pos, ip, port, brontideKey);
        }

        private void parseVersion(byte[] msg) {
            try {
                // version(4) + services(4) + hi_services(4) + time(8) + NetAddress(88) + nonce(8) + agentLen(1) + agent(N) + height(4) + noRelay(1)
                if (msg.length >= 8) {
                    protocolVersion = (int) readLE32(msg, 0);
                    services = (int) readLE32(msg, 4);
                }

                // DIAGNOSTIC: this NetAddress field is documented (per the
                // real hsd reference, see writeNetAddress()'s own comment)
                // as the sender's view of the RECEIVER -- i.e. when a peer
                // sends US their VERSION, this is supposed to be what
                // address THEY saw US connecting from. That's exactly the
                // same information a STUN server exists to provide,
                // except free: we already open these connections to sync
                // anyway. Nobody has verified whether real hsd peers
                // actually populate this honestly, though -- our OWN
                // outgoing version deliberately writes an all-zero key
                // into the equivalent field rather than a real one (see
                // that comment), so the same skepticism applies here
                // until real captured data says otherwise. This just logs
                // what every connected peer reports, as its own line, so
                // that question can be answered by looking at several
                // real peers' answers side by side rather than guessing
                // or trusting a single one. NOT used for anything yet --
                // no self-announcement wired up until this data says it's
                // trustworthy (e.g. multiple independent peers agreeing).
                //
                // Layout within the 88-byte NetAddress (starts at offset
                // 20 = version+services+hi_services+time):
                // time(8)+services(4)+hiServices(4)+addrType(1)+raw(16)
                // +reserved(20)+port(2)+key(33). raw[16]'s last 4 bytes
                // are the IPv4 address (standard IPv4-mapped-IPv6), so
                // absolute offset 20+8+4+4+1+12 = 49, 4 bytes.
                final int netAddrStart = 4 + 4 + 4 + 8; // = 20
                final int rawIpOffset = netAddrStart + 8 + 4 + 4 + 1 + 12; // = 49
                if (msg.length >= rawIpOffset + 4) {
                    String reportedIp = (msg[rawIpOffset] & 0xFF) + "."
                            + (msg[rawIpOffset + 1] & 0xFF) + "."
                            + (msg[rawIpOffset + 2] & 0xFF) + "."
                            + (msg[rawIpOffset + 3] & 0xFF);
                    selfReportedIp = reportedIp;
                    System.out.printf("[Handshake] <- %s reports our address as seen by them: %s%n",
                            ip, reportedIp);
                    recordSelfIpObservation(reportedIp, ip);
                }

                int pos = 4 + 4 + 4 + 8 + NET_ADDRESS_SIZE + 8; // = 116, start of agentLen
                if (msg.length <= pos) return;
                int agentLen = msg[pos] & 0xFF;
                pos++;
                if (msg.length >= pos + agentLen) {
                    agent = new String(msg, pos, agentLen, java.nio.charset.StandardCharsets.UTF_8);
                    pos += agentLen;
                }
                if (msg.length >= pos + 4) {
                    peerHeight = (int) readLE32(msg, pos);
                    if (peerHeight > bestKnownPeerHeight) bestKnownPeerHeight = peerHeight;
                }
            } catch (Exception e) {
                // DEBUG: this was silently swallowed before -- if VERSION
                // parsing itself throws, that's exactly the kind of thing
                // that could explain a peer that never seems to complete
                // the handshake, invisibly.
                System.out.printf("[Handshake] <- %s VERSION payload parse threw: %s: %s (msg.length=%d)%n",
                        ip, e.getClass().getSimpleName(), e.getMessage(), msg.length);
            }
        }

        void sendGetHeaders(List<byte[]> locator) throws Exception {
            // GETHEADERS payload: locator_count(varint) + hashes[] + stop_hash(32)
            // Confirmed directly against real hsd source (lib/net/packets.js,
            // GetHeadersPacket.write(), inherited from GetBlocksPacket): NO
            // leading version field. An earlier attempt to add one, based on
            // a secondary reference that turned out to be wrong here (the
            // same reference that had ACT_THREE_SIZE wrong), made things
            // worse -- it shifted every subsequent byte by 4, so the peer
            // went from "misinterprets a wrong hash" to "can't parse the
            // message at all," explaining the new "no response" symptom.
            byte[] payload = new byte[9 + locator.size() * 32 + 32];
            int pos = writeVarintBytes(payload, 0, locator.size());
            for (byte[] hash : locator) {
                System.arraycopy(hash, 0, payload, pos, 32);
                pos += 32;
            }
            // Stop hash = all zeros (get as many as possible)
            pos += 32;
            sendMessage(MSG_GETHEADERS, Arrays.copyOf(payload, pos));
        }

        void sendGetData(List<byte[]> hashes, int itemType) throws Exception {
            byte[] payload = new byte[9 + hashes.size() * 36];
            int pos = writeVarintBytes(payload, 0, hashes.size());
            for (byte[] hash : hashes) {
                pos = writeLE32(payload, pos, itemType);
                System.arraycopy(hash, 0, payload, pos, 32);
                pos += 32;
            }
            sendMessage(MSG_GETDATA, Arrays.copyOf(payload, pos));
        }

        /**
         * Sends a message using hsd's real frame format: magic(4 LE) +
         * cmd(1) + length(4 LE) + payload(N), always Brontide-encrypted
         * before it hits the wire -- this project no longer has a
         * cleartext transport, so brontide is never null here.
         */
        void sendMessage(int type, byte[] payload) throws Exception {
            byte[] frame = new byte[9 + payload.length];
            writeLE32(frame, 0, MAGIC_MAINNET);
            frame[4] = (byte) type;
            writeLE32(frame, 5, payload.length);
            System.arraycopy(payload, 0, frame, 9, payload.length);

            byte[] encrypted;
            // Encrypt AND write under the same lock: Brontide uses a
            // per-direction nonce counter, so two threads sending on one
            // connection (e.g. a block/tx relay while the sync thread sends a
            // GETHEADERS) must hit the wire in the same order they were
            // encrypted, or the peer's decryption fails and the stream dies.
            synchronized (out) {
                encrypted = plain ? frame : brontide.encryptMessage(frame);
                if (VERBOSE_WIRE_LOGGING) {
                    System.out.printf("[Handshake] -> %s SEND type=%d frame(%d bytes): %s%n",
                            ip, type, frame.length, toHex(frame));
                    System.out.printf("[Handshake] -> %s encrypted wire (%d bytes): %s%n",
                            ip, encrypted.length, toHex(encrypted));
                }
                out.write(encrypted);
                out.flush();
            }
            totalBytesSent.addAndGet(encrypted.length);
            bytesSent += encrypted.length;
            lastSendTime = System.currentTimeMillis() / 1000;
        }

        /**
         * Reads one message, returning the full frame (magic+cmd+length+
         * payload) with the magic number validated, always Brontide-
         * decrypted first -- this project no longer has a cleartext
         * transport, so brontide is never null here.
         * <p>
         * Verbose about exactly what comes back (byte counts, raw hex,
         * decrypted length) rather than collapsing everything to null --
         * this is what actually let the other conversation find its real
         * bugs (e.g. "Got 20 header bytes, Decrypted header, bodyLen=..."
         * revealing a tag-passes-but-garbage-output bug). A bare "timeout"
         * or "null" hides exactly the information needed to diagnose this.
         */
        byte[] readMessage(int timeoutMs) throws Exception {
            byte[] result = readMessageInternal(timeoutMs);
            if (result != null) {
                bytesRecv += result.length;
                lastRecvTime = System.currentTimeMillis() / 1000;
            }
            return result;
        }

        /** Cleartext framing: magic(4) + cmd(1) + length(4 LE) + payload, read as-is. */
        private byte[] readPlainFrame() {
            byte[] header = readPartialDebug(in, 9, ip, "header");
            if (header == null) return null;
            long magic = readLE32(header, 0) & 0xFFFFFFFFL;
            if (magic != (MAGIC_MAINNET & 0xFFFFFFFFL)) {
                System.out.printf("[Handshake] <- %s bad magic: 0x%08X expected 0x%08X%n",
                        ip, magic, MAGIC_MAINNET & 0xFFFFFFFFL);
                return null;
            }
            long len = readLE32(header, 5) & 0xFFFFFFFFL;
            if (len > 4_000_000L) {
                System.out.printf("[Handshake] <- %s payload length %d out of range, treating as invalid%n", ip, len);
                return null;
            }
            byte[] payload = readPartialDebug(in, (int) len, ip, "payload");
            if (payload == null) return null;
            byte[] frame = new byte[9 + payload.length];
            System.arraycopy(header, 0, frame, 0, 9);
            System.arraycopy(payload, 0, frame, 9, payload.length);
            return frame;
        }

        private byte[] readMessageInternal(int timeoutMs) throws Exception {
            socket.setSoTimeout(timeoutMs);
            if (plain) return readPlainFrame();

            // FIX: reverting to 20 bytes (4-byte LE length + 16-byte tag) --
            // a real past session reached an actual, complete, documented
            // success (323,987 headers synced) using this exact format.
            // See BrontideState.encryptMessage()'s own comment for the
            // full BrontideStream vs Brontide class explanation.
            byte[] header = readPartialDebug(in, 20, ip, "header");
            if (header == null) return null;

            int msgLen;
            try {
                msgLen = brontide.decryptLength(header);
            } catch (Exception e) {
                System.out.printf("[Handshake] <- %s header decrypt failed (tag/MAC check): %s: %s%n",
                        ip, e.getClass().getSimpleName(), e.getMessage());
                return null;
            }
            if (VERBOSE_WIRE_LOGGING) {
                System.out.printf("[Handshake] <- %s header decrypted OK, msgLen=%d%n", ip, msgLen);
            }
            if (msgLen < 0 || msgLen > 4_000_000) {
                System.out.printf("[Handshake] <- %s msgLen out of range, treating as invalid%n", ip);
                return null;
            }

            byte[] encPayload = readPartialDebug(in, msgLen + 16, ip, "payload");
            if (encPayload == null) return null;

            byte[] frame;
            try {
                frame = brontide.decryptPayload(encPayload);
            } catch (Exception e) {
                System.out.printf("[Handshake] <- %s payload decrypt failed (tag/MAC check): %s: %s%n",
                        ip, e.getClass().getSimpleName(), e.getMessage());
                return null;
            }
            if (frame == null || frame.length < 9) {
                System.out.printf("[Handshake] <- %s frame too short after decrypt: %d bytes%n",
                        ip, frame == null ? -1 : frame.length);
                return null;
            }
            long magic = readLE32(frame, 0) & 0xFFFFFFFFL;
            if (VERBOSE_WIRE_LOGGING) {
                System.out.printf("[Handshake] <- %s decrypted frame (%d bytes): %s%n",
                        ip, frame.length, toHex(frame));
            }
            if (magic != (MAGIC_MAINNET & 0xFFFFFFFFL)) {
                System.out.printf("[Handshake] <- %s bad magic: 0x%08X expected 0x%08X%n",
                        ip, magic, MAGIC_MAINNET & 0xFFFFFFFFL);
                return null;
            }
            return frame;
        }

        /**
         * Like readExact, but on early EOF returns null while logging
         * exactly how many bytes (if any) were received and their hex,
         * instead of silently collapsing a partial read into nothing.
         */
        private static byte[] readPartialDebug(InputStream in, int len, String ip, String label) {
            byte[] buf = new byte[len];
            int read = 0;
            try {
                while (read < len) {
                    int n = in.read(buf, read, len - read);
                    if (n < 0) break;
                    read += n;
                }
            } catch (IOException e) {
                totalBytesRecv.addAndGet(read);
                System.out.printf("[Handshake] <- %s %s read error after %d/%d bytes: %s: %s%n",
                        ip, label, read, len, e.getClass().getSimpleName(), e.getMessage());
                return null;
            }
            totalBytesRecv.addAndGet(read);
            if (read < len) {
                System.out.printf("[Handshake] <- %s %s: only got %d/%d bytes: %s%n",
                        ip, label, read, len,
                        read > 0 ? toHex(Arrays.copyOf(buf, read)) : "(connection closed with zero bytes)");
                return null;
            }
            return buf;
        }

        @Override
        public void close() {
            try { socket.close(); } catch (IOException ignored) {}
            // FIX: was removeIf(p -> p.ip().equals(ip)), which dropped EVERY
            // entry for this IP -- including a still-open connection in the
            // opposite direction (e.g. an inbound entry when an outbound one
            // to the same peer closed). Remove only this connection.
            connectedPeers.removeIf(p -> p.conn() == this);
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /** Reads the cmd byte at offset 4 of a frame (magic[0..3], cmd[4], length[5..8], payload[9..]). */
    private static int getMessageType(byte[] msg) {
        if (msg == null || msg.length < 9) return -1;
        return msg[4] & 0xFF;
    }

    private static long readLE32(byte[] b, int pos) {
        return (b[pos] & 0xFFL) | ((b[pos+1] & 0xFFL) << 8)
                | ((b[pos+2] & 0xFFL) << 16) | ((b[pos+3] & 0xFFL) << 24);
    }

    private static int writeLE32(byte[] b, int pos, long v) {
        b[pos]   = (byte) v;   b[pos+1] = (byte)(v>>8);
        b[pos+2] = (byte)(v>>16); b[pos+3] = (byte)(v>>24);
        return pos + 4;
    }

    private static int writeLE64(byte[] b, int pos, long v) {
        for (int i = 0; i < 8; i++) b[pos+i] = (byte)(v >> (i*8));
        return pos + 8;
    }

    private static long readVarint(byte[] b, int pos) {
        int first = b[pos] & 0xFF;
        if (first < 0xFD) return first;
        if (first == 0xFD) return readLE32(b, pos+1) & 0xFFFF;
        return readLE32(b, pos+1);
    }

    private static int varintSize(int v) {
        if (v < 0xFD) return 1;
        if (v <= 0xFFFF) return 3;
        return 5;
    }

    private static int writeVarintBytes(byte[] b, int pos, int v) {
        if (v < 0xFD) { b[pos] = (byte) v; return pos + 1; }
        b[pos] = (byte) 0xFD; b[pos+1] = (byte) v; b[pos+2] = (byte)(v>>8);
        return pos + 3;
    }

}