package handshake.node.chain;

import handshake.node.util.HexUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * The full, original Handshake reserved-names set, sourced directly
 * from the network's own official data repository,
 * handshake-org/hs-names-2023's build/updated/ output -- not
 * reconstructed or guessed at. Covers both this project's own
 * "ICANN Lockup" soft fork logic (real hsd PR #819/#828/#834,
 * activated mainnet block 210240) AND the base, original reserved-name
 * concept every one of those names was already part of since the 2020
 * mainnet launch, needed separately for CLAIM validation.
 * <p>
 * Two DISTINCT real-hsd checks this class exists to support -- see
 * isReserved() and isLockedUp() below, which deliberately do NOT
 * share logic, because real hsd's own rules.js doesn't either:
 *   - rules.isReserved(nameHash, height, network): was this name EVER
 *     part of the original reserved set (whether it has SINCE been
 *     released or not), AND is height still before the claim period
 *     ends. This is what gates CLAIM -- confirmed directly from
 *     chain.js's verifyCovenants(): the CLAIM branch checks
 *     isReserved(), never isLockedUp() at all.
 *   - rules.isLockedUp(nameHash, height, network): is this name
 *     CURRENTLY locked from being OPENed for a new auction. This is
 *     what gates OPEN specifically -- confirmed directly from the
 *     same method's OPEN branch, gated behind a separate
 *     VERIFY_COVENANTS_LOCKUP flag. Only ever true for a name that
 *     was never released; ICANN TLDs are locked permanently, every
 *     other still-locked name (Alexa Top 10K AND the "custom" list
 *     alike -- confirmed directly from real hsd's own isLockedUp(),
 *     which checks ONLY item.root for the permanent case, nothing
 *     else) for an additional four years past the claim period.
 * <p>
 * Real hsd's claimPeriod and this fork's own activation height are
 * separate named constants that happen to share the same value on
 * mainnet, by deliberate design (the fork was timed to coincide with
 * the original claim period ending) -- ICANNLOCKUP_HEIGHT below is
 * used for both, rather than declaring two identical constants.
 * <p>
 * Deliberately a static, read-only, bundled resource -- not a row in
 * this project's own mutable ChainDB. Every node on the network needs
 * the exact same, identical list forever; if this data ever lived in
 * a user-editable database instead, even an accidental local
 * discrepancy there would itself cause the same kind of Urkel-tree
 * divergence this whole class exists to prevent. Real hsd takes the
 * same approach -- this data is compiled directly into the software,
 * never fetched or stored as mutable state.
 */
public final class ReservedNames {

    private ReservedNames() {}

    /** See this class's own top comment on why one constant serves
     *  both roles. */
    public static final int ICANNLOCKUP_HEIGHT = 210_240;

    /** Alexa Top 10K names (and the "custom" list -- see this class's
     *  own top comment) get an ADDITIONAL four years of lockup past
     *  the claim period's own end, not a permanent one. Four years at
     *  144 blocks/day, the same constant BlockProcessor's own
     *  RENEWAL_WINDOW uses for identical reasoning. */
    public static final int ALEXA_ADDITIONAL_LOCKUP_BLOCKS = 4 * 365 * 144;

    public static final class Entry {
        public final String name;
        public final boolean root;
        public final boolean custom;
        public final boolean released;

        Entry(String name, boolean root, boolean custom, boolean released) {
            this.name = name;
            this.root = root;
            this.custom = custom;
            this.released = released;
        }

        /** ICANN TLDs are permanently locked once ICANNLOCKUP_HEIGHT is
         *  reached -- root ONLY, confirmed directly from real hsd's own
         *  isLockedUp() ("if (item.root) return true;", nothing else
         *  treated as permanent). The "custom" list follows the exact
         *  same four-year-past-claim-period rule as Alexa names, NOT
         *  this one -- a real, previously-shipped bug in this
         *  project's own port, found only by reading real source
         *  directly rather than inferring from a PR's own prose
         *  description, which had grouped TLDs and custom names
         *  together as "permanent" in a way the actual, deployed code
         *  does not. */
        public boolean isPermanent() {
            return root;
        }
    }

    private static final Map<String, Entry> BY_HASH = load();

    private static Map<String, Entry> load() {
        Map<String, Entry> map = new HashMap<>(96_000);
        try (InputStream in = ReservedNames.class.getResourceAsStream("/reserved_lockup.tsv")) {
            if (in == null) {
                throw new IllegalStateException(
                        "reserved_lockup.tsv is missing from the classpath -- this project cannot "
                                + "correctly sync past height " + ICANNLOCKUP_HEIGHT + " without it. "
                                + "See ReservedNames's own class comment for where this data comes from.");
            }
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.US_ASCII))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isEmpty()) continue;
                    String[] parts = line.split("\t", 3);
                    if (parts.length != 3) continue; // defensively skip a malformed line rather than crash startup over one bad row
                    String hash = parts[0];
                    String name = parts[1];
                    int flags = Integer.parseInt(parts[2]);
                    boolean released = flags == 3;
                    boolean root = !released && (flags & 1) != 0;
                    boolean custom = !released && (flags & 2) != 0;
                    map.put(hash, new Entry(name, root, custom, released));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load reserved_lockup.tsv", e);
        }
        return map;
    }

    /** Looks up a name by its already-computed Urkel tree hash (hex,
     *  lowercase, matching UrkelNameHash.hashName()'s own output
     *  encoding) -- returns null if this name was never part of the
     *  original reserved set at all (the overwhelming majority of
     *  real names processed). Exposed directly for callers that need
     *  the full Entry (name, category) rather than just a boolean --
     *  most call sites should prefer isReserved()/isLockedUp() below,
     *  which match real hsd's own two, deliberately distinct checks
     *  exactly. */
    public static Entry get(String nameHashHex) {
        return BY_HASH.get(nameHashHex);
    }

    public static Entry get(byte[] nameHash) {
        return get(hex(nameHash));
    }

    /** Matches real hsd's rules.isReserved() exactly -- gates CLAIM.
     *  True for ANY name that was ever part of the original reserved
     *  set (locked or since-released), as long as height is still
     *  before the claim period ends. Deliberately does NOT check
     *  root/custom/released category at all beyond "present in the
     *  full set" -- confirmed directly, real hsd's own isReserved()
     *  doesn't either. */
    public static boolean isReserved(byte[] nameHash, int height) {
        if (height >= ICANNLOCKUP_HEIGHT) return false;
        return get(nameHash) != null;
    }

    /** Matches real hsd's rules.isLockedUp() exactly -- gates OPEN
     *  specifically (confirmed directly from chain.js's
     *  verifyCovenants(): the OPEN branch checks this, the CLAIM
     *  branch checks isReserved() above instead, never this). False
     *  for anything already released, for anything before
     *  ICANNLOCKUP_HEIGHT, and for Alexa/custom names once their own
     *  additional four-year window has passed; true permanently only
     *  for root (ICANN TLD) entries. */
    public static boolean isLockedUp(byte[] nameHash, int height) {
        if (height < ICANNLOCKUP_HEIGHT) return false;
        Entry e = get(nameHash);
        if (e == null || e.released) return false;
        if (e.isPermanent()) return true;
        return height < ICANNLOCKUP_HEIGHT + ALEXA_ADDITIONAL_LOCKUP_BLOCKS;
    }

    public static int size() {
        return BY_HASH.size();
    }

    private static String hex(byte[] b) {
        return HexUtil.encode(b);
    }
}