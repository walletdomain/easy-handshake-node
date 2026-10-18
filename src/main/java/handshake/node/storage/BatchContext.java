package handshake.node.storage;

import org.rocksdb.*;

/**
 * One atomic write batch for a RocksDB instance, owned by a single thread at a time.
 * While open, the owning thread's writes are buffered in a WriteBatchWithIndex and its reads see them (falling
 * through to the database for everything else); every other thread reads committed data only. commit() applies the
 * whole batch in one atomic RocksDB write.
 */
final class BatchContext {
    private final RocksDB db;
    private volatile Thread owner;
    private WriteBatchWithIndex wbwi;
    private ReadOptions readOptions;
    private WriteOptions writeOptions;

    BatchContext(RocksDB db) { this.db = db; }

    /** True only on the thread that opened the batch. */
    boolean active() { return owner == Thread.currentThread(); }

    synchronized void begin() {
        if (owner != null) throw new IllegalStateException("a write batch is already open (owner " + owner.getName() + ")");
        wbwi = new WriteBatchWithIndex(true);
        readOptions = new ReadOptions();
        writeOptions = new WriteOptions();
        owner = Thread.currentThread();
    }

    void put(ColumnFamilyHandle cf, byte[] k, byte[] v) throws RocksDBException { wbwi.put(cf, k, v); }
    void delete(ColumnFamilyHandle cf, byte[] k) throws RocksDBException { wbwi.delete(cf, k); }

    byte[] get(ColumnFamilyHandle cf, byte[] k) throws RocksDBException {
        return wbwi.getFromBatchAndDB(db, cf, readOptions, k);
    }

    synchronized void commit() {
        if (!active()) throw new IllegalStateException("commitBatch() from a thread that does not own the batch");
        try {
            db.write(writeOptions, wbwi);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        } finally {
            release();
        }
    }

    synchronized void discard() {
        if (owner == null) return;
        if (!active()) throw new IllegalStateException("discardBatch() from a thread that does not own the batch");
        release();
    }

    private void release() {
        owner = null;
        wbwi.close(); readOptions.close(); writeOptions.close();
        wbwi = null; readOptions = null; writeOptions = null;
    }
}
