package handshake.node;

import java.io.PrintStream;
import java.util.List;

/**
 * RE-ARCHITECTURE: shared decode-and-print logic for dumping every
 * covenant transaction across a block-height window, pulled out of
 * UrkelMismatchDiagnostics (the automatic dump fired the instant a real
 * tree-root mismatch is detected) and InspectCommitWindow (the manual,
 * ad-hoc version of the exact same inspection, run by hand against an
 * already-closed database) -- before this class existed, the two
 * carried nearly line-for-line identical copies of this (same window
 * walk, same per-covenant printf format strings, same current-NameEntry
 * cross-reference), confirmed by direct comparison. A fix or format
 * change made to one was never guaranteed to reach the other; now there
 * is exactly one place this logic can drift from what the real
 * validator does.
 *
 * Deliberately reuses BlockProcessor.parseBlockTxs()/extractName()
 * rather than re-implementing covenant decoding, for the same reason
 * both original callers did: this tool's output can never silently
 * drift from what the real validator actually believes about a given
 * transaction.
 *
 * Read-only: only ever calls db.getBlock()/db.getNameByHash() and writes
 * to the PrintStream the caller supplies. Never writes to ChainDB.
 */
final class CovenantDumpUtil {
    private CovenantDumpUtil() {}

    /** Walks windowStart..commitHeight (inclusive) in db, printing every
     *  covenant transaction found via printCovenant() below to out.
     *  Returns the total covenant-transaction count printed. */
    static int dumpWindow(PrintStream out, ChainDB db, int windowStart, int commitHeight) {
        int covenantTxCount = 0;
        for (int height = windowStart; height <= commitHeight; height++) {
            byte[] rawBlock = db.getBlock(height);
            if (rawBlock == null) {
                out.println("Height " + height + ": NO BLOCK STORED LOCALLY -- skipping "
                        + "(this window is expected to be fully present; a gap here is itself "
                        + "worth knowing about).");
                continue;
            }
            List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
            boolean printedHeightHeader = false;
            for (TxParser.ParsedTx tx : txs) {
                String txid = TxParser.computeTxid(tx.raw);
                for (int i = 0; i < tx.outputs.size(); i++) {
                    TxParser.Output o = tx.outputs.get(i);
                    if (o.covenant == null || o.covenant.type == TxParser.COV_NONE) continue;
                    if (!printedHeightHeader) {
                        out.println("--- Height " + height + " ---");
                        printedHeightHeader = true;
                    }
                    covenantTxCount++;
                    printCovenant(out, db, txid, i, o);
                }
            }
        }
        return covenantTxCount;
    }

    /** Prints one covenant transaction's full decoded detail, plus the
     *  touched name's CURRENT persisted state in db for direct
     *  cross-reference (e.g. a REVEAL that doesn't match the currently
     *  recorded highest bid, or a RENEW on a name recorded as expired).
     *  That current-state line reflects the FINAL state after everything
     *  through db's own tip has already been applied -- a sanity check,
     *  not a step-by-step trace. */
    static void printCovenant(PrintStream out, ChainDB db, String txid,
                              int outputIndex, TxParser.Output o) {
        TxParser.Covenant cov = o.covenant;
        String typeName = covenantTypeName(cov.type);
        byte[] nameHashBytes = cov.items.isEmpty() ? null : cov.items.get(0).data;
        String nameHash = (nameHashBytes != null && nameHashBytes.length == 32)
                ? HexUtil.encode(nameHashBytes) : "(missing/malformed)";
        String name;
        try {
            name = BlockProcessor.extractName(cov.items, cov.type);
        } catch (Exception e) {
            name = "(extractName threw: " + e + ")";
        }

        out.printf("  tx %s output %d: %s  value=%d  nameHash=%s  name=\"%s\"%n",
                txid, outputIndex, typeName, o.value, nameHash, name);
        for (int j = 0; j < cov.items.size(); j++) {
            byte[] data = cov.items.get(j).data;
            out.println("      item[" + j + "]: " + (data == null ? "(null)" : HexUtil.encode(data)
                    + "  (" + data.length + " bytes)"));
        }

        if (nameHashBytes != null && nameHashBytes.length == 32 && db != null) {
            ChainDB.NameEntry entry = db.getNameByHash(nameHash);
            if (entry != null) {
                out.printf("      current entry: state=%s height=%d renewal=%d "
                                + "value=%d highest=%d registered=%b expired=%b revoked=%d transfer=%d%n",
                        entry.state, entry.height, entry.renewal, entry.value, entry.highest,
                        entry.registered, entry.expired, entry.revoked, entry.transfer);
            } else {
                out.println("      current entry: (no NameEntry found for this hash)");
            }
        }
    }

    static String covenantTypeName(int type) {
        return switch (type) {
            case TxParser.COV_NONE -> "NONE";
            case TxParser.COV_CLAIM -> "CLAIM";
            case TxParser.COV_OPEN -> "OPEN";
            case TxParser.COV_BID -> "BID";
            case TxParser.COV_REVEAL -> "REVEAL";
            case TxParser.COV_REDEEM -> "REDEEM";
            case TxParser.COV_REGISTER -> "REGISTER";
            case TxParser.COV_UPDATE -> "UPDATE";
            case TxParser.COV_RENEW -> "RENEW";
            case TxParser.COV_TRANSFER -> "TRANSFER";
            case TxParser.COV_FINALIZE -> "FINALIZE";
            case TxParser.COV_REVOKE -> "REVOKE";
            default -> "UNKNOWN(" + type + ")";
        };
    }
}