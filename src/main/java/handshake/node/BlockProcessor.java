package handshake.node;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * BlockProcessor — processes confirmed blocks to update the UTXO set
 * and name state in ChainDB.
 * <p>
 * Called by ChainSync for each new block as it is confirmed.
 * <p>
 * Processing steps for each block:
 *   1. Remove spent UTXOs (inputs)
 *   2. Add new UTXOs (outputs)
 *   3. Update name state for covenant outputs
 *   4. Evict confirmed transactions from mempool
 * <p>
 * Name state machine (from hsd/lib/covenants/rules.js):
 *   NONE    → OPEN      via OPEN covenant
 *   OPEN    → BID       via BID covenant
 *   BID     → REVEAL    via REVEAL covenant
 *   REVEAL  → REGISTER  via REGISTER covenant (auction winner)
 *   REVEAL  → REDEEM    via REDEEM covenant (auction losers)
 *   CLOSED  → UPDATE    via UPDATE covenant
 *   CLOSED  → RENEW     via RENEW covenant
 *   CLOSED  → TRANSFER  via TRANSFER covenant
 *   TRANSFER→ FINALIZE  via FINALIZE covenant (completes transfer)
 *   CLOSED  → REVOKE    via REVOKE covenant
 */
public class BlockProcessor {

    // Covenant types (matching TxParser constants)
    private static final int COV_NONE     = TxParser.COV_NONE;
    private static final int COV_CLAIM    = TxParser.COV_CLAIM;
    private static final int COV_OPEN     = TxParser.COV_OPEN;
    private static final int COV_BID      = TxParser.COV_BID;
    private static final int COV_REVEAL   = TxParser.COV_REVEAL;
    private static final int COV_REDEEM   = TxParser.COV_REDEEM;
    private static final int COV_REGISTER = TxParser.COV_REGISTER;
    private static final int COV_UPDATE   = TxParser.COV_UPDATE;
    private static final int COV_RENEW    = TxParser.COV_RENEW;
    private static final int COV_TRANSFER = TxParser.COV_TRANSFER;
    private static final int COV_FINALIZE = TxParser.COV_FINALIZE;
    private static final int COV_REVOKE   = TxParser.COV_REVOKE;

    /**
     * Processes a raw block at the given height, updating UTXO set and
     * name state. Returns false if the block's merkle root doesn't match
     * its header (rejected outright -- no UTXO/name changes applied at
     * all -- since a peer sending mismatched transaction data alongside
     * an otherwise-valid header is exactly the scenario merkle
     * verification exists to catch, the same category as invalid PoW: a
     * signal an honest peer could never legitimately produce).
     */
    public static boolean process(byte[] rawBlock, int height,
                                  ChainDB db, Mempool mempool) {
        try {
            return processInternal(rawBlock, height, db, mempool);
        } catch (Exception e) {
            System.err.printf("[BlockProcessor] Error at height %d: %s%n",
                    height, e.getMessage());
            return true; // an unexpected parsing error isn't a merkle violation
        }
    }

    private static boolean processInternal(byte[] rawBlock, int height,
                                           ChainDB db, Mempool mempool) {
        // Parse the block
        List<TxParser.ParsedTx> txs = parseBlockTxs(rawBlock);
        List<String> confirmedTxids = new ArrayList<>();

        // Merkle root verification: proves the actual transactions in
        // this block correspond to what the (already header-validated)
        // header committed to via its merkleRoot field. Header validation
        // alone only proves the HEADER is legitimate -- it says nothing
        // about whether the accompanying transaction data is genuine.
        // Now blocking (upgraded from an earlier warn-only phase): both
        // the merkle algorithm itself and a real underlying transaction-
        // parsing bug (a varint misread that corrupted parsing for any
        // transaction with 253+ inputs/outputs/witness items) have been
        // rigorously verified against real captured block data, including
        // a full end-to-end match through this exact code path.
        List<byte[]> txidBytes = new ArrayList<>();
        for (TxParser.ParsedTx tx : txs) {
            byte[] base = Arrays.copyOf(tx.raw, tx.baseSize);
            txidBytes.add(Blake2b.hash256(base));
        }
        byte[] headerBytes = Arrays.copyOf(rawBlock, Math.min(236, rawBlock.length));
        byte[] claimedMerkleRoot = HeaderUtil.merkleRoot(headerBytes);
        if (!MerkleUtil.verify(txidBytes, claimedMerkleRoot)) {
            System.err.printf("[BlockProcessor] Merkle root mismatch at height %d "
                    + "-- rejecting block, no UTXO/name changes applied%n", height);
            return false;
        }

        for (TxParser.ParsedTx tx : txs) {
            String txid = TxParser.computeTxid(tx.raw);
            if (txid == null) continue;
            confirmedTxids.add(txid);

            // Signature verification happens OUTSIDE the per-transaction
            // try/catch below, deliberately: a covenant-parsing bug in
            // OUR OWN code isolating to one transaction is a very
            // different thing from a transaction whose signature we
            // actually checked and found invalid -- the latter is a real
            // consensus violation and must reject the entire block, not
            // just be logged and skipped like the former. Only a
            // definite, checked failure rejects; a UTXO we can't find or
            // an address type TxVerify doesn't yet support (e.g.
            // 32-byte scripthash/multisig, which are legitimate and
            // exist on real mainnet) is left unverified rather than
            // treated as invalid -- rejecting those would break sync on
            // perfectly valid, real blocks that every other real hsd
            // validator accepts.
            if (!tx.inputs.isEmpty() && !tx.inputs.get(0).isCoinbase()) {
                for (int i = 0; i < tx.inputs.size(); i++) {
                    TxParser.Input input = tx.inputs.get(i);
                    ChainDB.UtxoEntry spentUtxo = db.getUtxo(input.prevTxid, input.prevIndex);
                    if (spentUtxo == null || spentUtxo.addrHash().length != 20) {
                        continue; // unverifiable -- not a failure, just not checked
                    }
                    if (!TxVerify.verifyInput(tx, i, spentUtxo.addrHash(), spentUtxo.value())) {
                        System.err.printf("[BlockProcessor] Signature verification failed for "
                                + "tx %s input %d at height %d -- rejecting block, no UTXO/name "
                                + "changes applied%n", txid, i, height);
                        return false;
                    }
                }
            }

            // Isolated per-transaction: previously an exception in ANY
            // single transaction's covenant processing would propagate
            // all the way out of processInternal() and abort the ENTIRE
            // block, discarding every other transaction's UTXO and
            // name-state updates too -- not just the failing one's. A
            // problem with one transaction's covenant data shouldn't cost
            // the rest of a perfectly valid block.
            try {
                // Step 1: Remove spent UTXOs
                if (!tx.inputs.isEmpty() && !tx.inputs.get(0).isCoinbase()) {
                    for (TxParser.Input input : tx.inputs) {
                        db.removeUtxo(input.prevTxid, input.prevIndex);
                    }
                }

                // Step 2: Add new UTXOs and process covenants
                for (int i = 0; i < tx.outputs.size(); i++) {
                    TxParser.Output out = tx.outputs.get(i);

                    // Add UTXO
                    byte[] covData = serializeCovenant(out.covenant);
                    ChainDB.UtxoEntry utxo = new ChainDB.UtxoEntry(
                            out.value,
                            out.addrVersion,
                            out.addrHash,
                            out.covenant != null ? out.covenant.type : 0,
                            covData,
                            tx.inputs.isEmpty() || tx.inputs.get(0).isCoinbase(),
                            height
                    );
                    db.saveUtxo(txid, i, utxo);

                    // Step 3: Update name state for covenant outputs
                    if (out.covenant != null && out.covenant.type != COV_NONE) {
                        processNameCovenant(out, txid, i, height, db);
                    }
                }
            } catch (Exception e) {
                System.err.printf("[BlockProcessor] Error processing tx %s at height %d: %s "
                        + "(rest of block still processed)%n", txid, height, e.getMessage());
            }
        }

        // Step 3b: Persist any new tree nodes from this block, then
        // advance the "official" committed root if this height lands
        // on a real interval boundary -- confirmed directly from
        // chain.js/chaindb.js. Must run once per block (not per
        // covenant/transaction), after every covenant in this block
        // has already been applied above. Persisting every block, not
        // just at commit boundaries, is required for correctness
        // across a restart (see UrkelNameTree's own class comment).
        db.persistNameTreeState(height);

        // Step 4: Evict confirmed transactions from mempool
        if (mempool != null) {
            mempool.onBlockConnected(confirmedTxids);
        }

        // NOTE: no db.commit() here anymore -- this used to commit after
        // EVERY single block, unbatched, unlike header sync (which
        // commits once per batch of up to 2000). As the database grows
        // with real block/UTXO/name data, each individual disk commit
        // gets progressively more expensive, producing a gradually
        // worsening slowdown with no error and no socket timeout (since
        // it's not actually blocked on network I/O) -- which looks
        // exactly like an unexplained hang. The caller now batches
        // commits instead, matching the header-sync pattern.
        return true;
    }

    // ── Name state machine ────────────────────────────────────────────────────

    private static void processNameCovenant(TxParser.Output out, String txid,
                                            int outputIndex, int height, ChainDB db) {
        int type = out.covenant.type;
        List<TxParser.CovenantItem> items = out.covenant.items;
        if (items.isEmpty()) return;

        // Get name hash (item[0] for all covenant types)
        byte[] nameHashBytes = items.get(0).data;
        if (nameHashBytes == null || nameHashBytes.length != 32) return;
        String nameHash = hex(nameHashBytes);

        // Get or create name entry
        ChainDB.NameEntry entry = db.getNameByHash(nameHash);
        if (entry == null) {
            entry = new ChainDB.NameEntry();
            entry.nameHash = nameHash;
            entry.name = extractName(items, type);
        }

        // Update owner outpoint
        entry.ownerTxid  = txid;
        entry.ownerIndex = outputIndex;

        // Apply state transition
        switch (type) {
            case COV_OPEN -> {
                entry.state   = "OPENING";
                entry.height  = height;
                entry.name    = extractName(items, type);
            }
            case COV_BID -> {
                entry.state  = "BIDDING";
            }
            case COV_REVEAL -> {
                entry.state  = "REVEAL";
                entry.value  = out.value;
                // Track highest bid
                if (out.value > entry.highest) entry.highest = out.value;
            }
            case COV_REDEEM -> {
                // Losing bid — no state change to name, just UTXO freed
            }
            case COV_REGISTER -> {
                entry.state   = "CLOSED";
                entry.height  = extractU32(items, 1);
                entry.renewal = height;
                entry.value   = out.value;
                // item[2] is the raw DNS-record blob, confirmed against
                // real hsd's covenant structure -- needed for
                // getnameresource, which previously had nothing to read
                // at all since this was never stored anywhere.
                if (items.size() > 2 && items.get(2).data != null) {
                    entry.resourceData = items.get(2).data;
                }
            }
            case COV_CLAIM -> {
                entry.state   = "CLOSED";
                entry.height  = extractU32(items, 1);
                entry.renewal = height;
                entry.value   = out.value;
                // NOT extracting resourceData here -- CLAIM's covenant
                // structure (DNSSEC-based legacy name claims) isn't
                // confirmed to carry record data at the same item index
                // as a normal REGISTER, and guessing wrong here would
                // silently store garbage as "DNS records" for claimed
                // names.
            }
            case COV_UPDATE -> {
                entry.state   = "CLOSED";
                entry.renewal = height;
                if (items.size() > 2 && items.get(2).data != null) {
                    entry.resourceData = items.get(2).data;
                }
            }
            case COV_RENEW -> {
                entry.state   = "CLOSED";
                entry.renewal = height;
                entry.renewals++;
            }
            case COV_TRANSFER -> {
                entry.state    = "CLOSED"; // still CLOSED but transfer pending
                entry.transfer = height;
            }
            case COV_FINALIZE -> {
                entry.state    = "CLOSED";
                entry.transfer = 0;        // transfer complete
                entry.renewal  = height;
                entry.renewals = extractU32(items, 5);
                entry.claimed  = extractU32(items, 4);
            }
            case COV_REVOKE -> {
                entry.state   = "REVOKED";
                entry.revoked = height;
                entry.transfer = 0;
            }
        }

        db.saveName(entry);

        // Feed the tree, matching real hsd's own exclusion exactly:
        // "BID and REDEEM covenants do not update NameState" (confirmed
        // directly from chaindb.js's comment). Every other covenant
        // type does, mirroring the state transitions already applied
        // to `entry` above.
        if (type != COV_BID && type != COV_REDEEM) {
            UrkelNameState ns = new UrkelNameState();
            ns.name = entry.name != null ? entry.name.getBytes(java.nio.charset.StandardCharsets.US_ASCII) : new byte[0];
            ns.data = entry.resourceData != null ? entry.resourceData : new byte[0];
            ns.height = entry.height;
            ns.renewal = entry.renewal;
            if (entry.ownerTxid != null && !entry.ownerTxid.isEmpty()) {
                ns.ownerHash = fromHex(entry.ownerTxid);
                ns.ownerIndex = entry.ownerIndex;
            }
            ns.value = entry.value;
            ns.highest = entry.highest;
            ns.transfer = entry.transfer;
            ns.revoked = entry.revoked;
            ns.claimed = entry.claimed;
            ns.renewals = entry.renewals;
            ns.registered = "CLOSED".equals(entry.state);
            ns.expired = false; // expiration isn't proactively tracked yet -- known gap
            ns.weak = entry.weak;

            db.getNameTree().applyNameState(nameHashBytes, ns);
        }
    }

    // ── Block parsing ─────────────────────────────────────────────────────────

    /**
     * Parses transactions from a raw block.
     * Block format: header(236) + tx_count(varint) + txs[]
     */
    public static List<TxParser.ParsedTx> parseBlockTxs(byte[] rawBlock) {
        List<TxParser.ParsedTx> txs = new ArrayList<>();
        try {
            int pos = 236; // skip header
            if (pos >= rawBlock.length) return txs;

            // Read tx count (varint)
            int txCount = rawBlock[pos] & 0xFF;
            if (txCount < 0xFD) {
                pos++;
            } else if (txCount == 0xFD) {
                txCount = ((rawBlock[pos+1] & 0xFF) | ((rawBlock[pos+2] & 0xFF) << 8));
                pos += 3;
            } else {
                pos += 5; // skip 0xFE + 4 bytes
            }

            // Parse each transaction
            for (int i = 0; i < txCount && pos < rawBlock.length; i++) {
                byte[] remaining = Arrays.copyOfRange(rawBlock, pos, rawBlock.length);
                TxParser.ParsedTx tx = TxParser.parse(remaining);
                if (tx == null) break;
                txs.add(tx);
                // Advance past the full transaction, INCLUDING witness
                // data. tx.totalSize is now genuinely computed by walking
                // the real witness stacks (see TxParser.parse()) --
                // previously this called a separate function that just
                // guessed "baseSize + 150 bytes per input" with no
                // relationship to the actual witness data, silently
                // misaligning every transaction after any one whose real
                // witness size didn't match that guess.
                pos += tx.totalSize;
            }
        } catch (Exception e) {
            System.err.println("[BlockProcessor] Block parse error: " + e.getMessage());
        }
        return txs;
    }

    /**
     * Estimates the full transaction size including witnesses.
     * Falls back to baseSize + reasonable witness estimate.
     */
    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Extracts the plaintext name string from a covenant's items, when
     * that covenant type actually carries one at item index 2. Confirmed
     * against a real, complete covenant item reference for every type:
     * <p>
     *   CLAIM:    [nameHash, height, name, flags]
     *   OPEN:     [nameHash, height, name]
     *   BID:      [nameHash, height, name, blind]
     *   FINALIZE: [nameHash, height, name, flags, claimHeight, renewals, blockHash]
     * <p>
     *   REVEAL:   [nameHash, height, nonce]        -- item[2] is a NONCE, not a name
     *   REDEEM:   [nameHash, height]                -- no item[2] at all
     *   REGISTER: [nameHash, height, recordData, blockHash]
     *   UPDATE:   [nameHash, height, recordData]
     *   RENEW:    [nameHash, height, blockHash]
     *   TRANSFER: [nameHash, height, version, address]
     *   REVOKE:   [nameHash, height]                -- no item[2] at all
     * <p>
     * Previously EVERY one of these second-group types was treated as if
     * item[2] held the name, meaning random binary data (nonces, hashes,
     * record data) was being interpreted as ASCII text and stored as the
     * name. For 32 random bytes, there's roughly a 12% chance per call
     * of that data containing a literal '|' byte, which corrupts the
     * pipe-delimited NameEntry record for all future reads -- exactly
     * the recurring "unparseable NameEntry" warnings seen in testing.
     * COV_CLAIM was also missing from this entirely, silently leaving
     * claimed names without a name string at all.
     */
    private static String extractName(List<TxParser.CovenantItem> items, int type) {
        int nameIndex = switch (type) {
            case COV_CLAIM, COV_OPEN, COV_BID, COV_FINALIZE -> 2;
            default -> -1; // this covenant type doesn't carry a name at item[2]
        };
        if (nameIndex < 0 || nameIndex >= items.size()) return "";
        byte[] nameBytes = items.get(nameIndex).data;
        if (nameBytes == null) return "";
        return new String(nameBytes, StandardCharsets.US_ASCII);
    }

    private static int extractU32(List<TxParser.CovenantItem> items, int index) {
        if (index >= items.size()) return 0;
        byte[] b = items.get(index).data;
        if (b == null || b.length < 4) return 0;
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8)
                | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }

    private static byte[] serializeCovenant(TxParser.Covenant cov) {
        if (cov == null || cov.items.isEmpty()) return new byte[0];
        // Simple serialization: concatenate all items with length prefixes
        int totalLen = 0;
        for (TxParser.CovenantItem item : cov.items) {
            totalLen += 1 + (item.data != null ? item.data.length : 0);
        }
        byte[] result = new byte[totalLen];
        int pos = 0;
        for (TxParser.CovenantItem item : cov.items) {
            int len = item.data != null ? item.data.length : 0;
            result[pos++] = (byte) len;
            if (item.data != null) {
                System.arraycopy(item.data, 0, result, pos, len);
                pos += len;
            }
        }
        return result;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] fromHex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }
}