package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.FileHeader;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Low-level, whole-block read/write access to a single encrypted (cipher-side)
 * file.
 *
 * <p>Encapsulates the per-file header (file id) and block-wise authenticated
 * content encryption (AES-256-GCM, XChaCha20-Poly1305 or AES-SIV, depending on
 * the supplied {@link ContentEnc}). It exposes only whole-block operations;
 * byte- and range-level buffering, read-modify-write of partial blocks and
 * position tracking live in {@link BlockBufferedChannel}, which sits on top of
 * the shared {@link SharedCipherFile}.</p>
 *
 * <p>Owns the {@link ContentEnc} it is opened with: {@link #close()} wipes that
 * helper's key material, so a file's content key does not outlive the file.</p>
 */
public final class CipherFile implements AutoCloseable {

    /** The underlying cipher file channel. */
    private final CipherChannel channel;

    /** Whether the channel was opened for writing. */
    private final boolean writable;

    /** The content-encryption helper. */
    private final ContentEnc enc;

    /** The crash-safety journal, or {@code null} for standalone test instances. */
    private @Nullable CipherJournal journal;

    /** Scratch buffer for a single ciphertext block. */
    private final byte[] blockCipher;

    /** Scratch buffer for a single plaintext block. */
    private final byte[] blockPlain;

    /**
     * Bounds the number of encrypted blocks buffered before they are committed
     * together. A larger batch amortizes the journal and data fsyncs over many
     * blocks without letting a huge write exhaust memory.
     */
    private static final int MAX_PENDING_BLOCKS = 1024;

    /**
     * Block updates written since the last commit, keyed by block number so a
     * later write to the same block replaces the earlier one. Only used when a
     * journal is present; standalone instances write through immediately.
     */
    private final Map<Long, PendingBlock> pendingBlocks = new LinkedHashMap<>();

    /** The file id from the header, or {@code null} for an empty file. */
    private byte @Nullable [] fileId;

    /** Whether the file id has been loaded from the header. */
    private boolean fileIdLoaded;

    /** Whether the file has been modified since the last {@link #force(boolean)}. */
    private boolean dirty;

    /**
     * Whether the current journal record has not yet been fully applied and
     * forced. Such a journal must survive close so the next open can finish the
     * update; only a record whose data is already durable may be cleared.
     */
    private boolean journalPending;

    /**
     * Whether the pending journal record may already have modified the main
     * file. A record whose write failed before touching the file can be
     * discarded on close; one that may have left a partial write must stay so
     * the next writable open can finish or replace it.
     */
    private boolean journalFileTouched;

    /**
     * One encrypted block waiting to be published in the next journal record.
     */
    private static final class PendingBlock {

        /** The block number. */
        private final long blockNo;

        /** The encrypted block. */
        private final byte[] cipher;

        /** The plaintext length represented by {@link #cipher}. */
        private final int plainLen;

        /**
         * Creates a pending block.
         *
         * @param blockNo  the block number
         * @param cipher   the encrypted block
         * @param plainLen the plaintext length
         */
        private PendingBlock(long blockNo, byte[] cipher, int plainLen) {
            this.blockNo = blockNo;
            this.cipher = cipher;
            this.plainLen = plainLen;
        }
    }

    /**
     * A plaintext block update handed to {@link #writeBlocks(List)}.
     */
    static final class BlockUpdate {

        /** The block number. */
        final long blockNo;

        /** The plaintext buffer. */
        final byte[] plain;

        /** The offset within {@link #plain}. */
        final int offset;

        /** The number of plaintext bytes. */
        final int length;

        /**
         * Creates a block update.
         *
         * @param blockNo the block number
         * @param plain   the plaintext buffer
         * @param offset  the offset within the buffer
         * @param length  the number of bytes
         */
        BlockUpdate(long blockNo, byte[] plain, int offset, int length) {
            this.blockNo = blockNo;
            this.plain = Objects.requireNonNull(plain, "plain");
            this.offset = offset;
            this.length = length;
        }
    }

    /**
     * Creates an instance over an open channel.
     *
     * @param channel  the underlying file channel
     * @param enc      the content-encryption helper
     * @param writable whether the channel permits writes
     * @param journal  the crash-safety journal, or {@code null}
     */
    private CipherFile(CipherChannel channel, ContentEnc enc, boolean writable,
                       @Nullable CipherJournal journal) {
        this.channel = channel;
        this.enc = enc;
        this.writable = writable;
        this.journal = journal;
        this.blockCipher = new byte[(int) enc.cipherBS()];
        this.blockPlain = new byte[(int) enc.plainBS()];
    }

    /**
     * Creates an instance over an open, writable channel.
     *
     * @param channel the underlying file channel
     * @param enc     the content-encryption helper
     */
    @SuppressWarnings("UnusedMethod") // accessed reflectively by tests
    private CipherFile(CipherChannel channel, ContentEnc enc) {
        this(channel, enc, true, null);
    }

    /**
     * Opens a cipher-side file for random access over an already-open channel.
     *
     * @param channel  the underlying channel
     * @param enc      the content-encryption helper (determines the cipher)
     * @param writable whether the file should be opened for writing
     * @return the opened cipher file
     * @throws NullPointerException if {@code channel} or {@code enc} is {@code null}
     */
    static CipherFile open(CipherChannel channel, ContentEnc enc, boolean writable) {
        return open(channel, enc, writable, null);
    }

    /**
     * Opens a cipher-side file for random access over an already-open channel,
     * with an optional write-ahead journal for crash-safe block updates.
     *
     * @param channel  the underlying channel
     * @param enc      the content-encryption helper (determines the cipher)
     * @param writable whether the file should be opened for writing
     * @param journal  the crash-safety journal, or {@code null}
     * @return the opened cipher file
     * @throws NullPointerException if {@code channel} or {@code enc} is {@code null}
     */
    static CipherFile open(CipherChannel channel, ContentEnc enc, boolean writable,
                           @Nullable CipherJournal journal) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(enc, "enc");
        return new CipherFile(channel, enc, writable, journal);
    }

    /**
     * Returns the plaintext block size in bytes.
     *
     * @return the plaintext block size
     */
    int blockSize() {
        return (int) enc.plainBS();
    }

    /**
     * Returns the maximum plaintext size supported by the content cipher.
     *
     * @return the maximum plaintext size in bytes
     */
    long maxPlainSize() {
        return enc.maxPlainSize();
    }

    /**
     * Checks that writing {@code len} plaintext bytes at {@code off} in
     * {@code blockNo} stays within the maximum plaintext size.
     *
     * @param blockNo the block number
     * @param off     the plaintext offset within the block
     * @param len     the number of plaintext bytes
     * @throws IOException if the range is invalid or exceeds the maximum
     *                     plaintext size
     */
    private void checkPlainRange(long blockNo, int off, int len) throws IOException {
        if (blockNo < 0 || off < 0 || len < 0) {
            throw new IOException("invalid plaintext block range: block " + blockNo
                    + ", offset " + off + ", length " + len);
        }
        long max = maxPlainSize();
        if (blockNo > max / enc.plainBS()) {
            throw new IOException("plaintext block exceeds maximum size: " + blockNo);
        }
        long end = blockNo * enc.plainBS() + off + len;
        if (end > max) {
            throw new IOException("plaintext write exceeds maximum size: " + end + " > " + max);
        }
    }

    /**
     * Returns the file id from the header, or {@code null} if the file is empty.
     *
     * @return a copy of the 16-byte file id, or {@code null} for an empty file
     * @throws IOException if the file header is corrupt
     */
    public synchronized byte @Nullable [] fileId() throws IOException {
        byte[] id = loadFileId();
        return id == null ? null : id.clone();
    }

    /**
     * Returns the plaintext size of the file, derived from the ciphertext size.
     *
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    public synchronized long plainSize() throws IOException {
        long size = enc.cipherSizeToPlainSize(channel.size());
        for (PendingBlock block : pendingBlocks.values()) {
            long end = enc.blockNoToPlainOff(block.blockNo) + block.plainLen;
            if (end > size) {
                size = end;
            }
        }
        return size;
    }

    /**
     * Returns the ciphertext end offset of the furthest pending block, or
     * {@code -1} when nothing is pending.
     *
     * @return the pending ciphertext end, or {@code -1}
     */
    private long pendingCipherEnd() {
        long end = -1;
        for (PendingBlock block : pendingBlocks.values()) {
            long blockEnd = enc.blockNoToCipherOff(block.blockNo) + block.cipher.length;
            if (blockEnd > end) {
                end = blockEnd;
            }
        }
        return end;
    }

    /**
     * Replays a pending write-ahead journal, if one exists. Must be called
     * before the file is used after opening it.
     *
     * <p>Only a writable file may replay or remove a journal, because recovery
     * happens under the cipher root lock that a read-only instance does not
     * hold. A read-only file with a journal present fails instead of replaying
     * it, so it can never roll back a live writer's later update.</p>
     *
     * @throws IOException if a pending journal cannot be applied, or if one is
     *                     present on a read-only file
     */
    void recoverJournal() throws IOException {
        if (journal == null) {
            return;
        }
        CipherJournal.Record record = journal.read();
        if (record == null) {
            if (journal.exists()) {
                // The journal is unparseable. Only a writable open may discard
                // it; a read-only open must not write to the cipher directory.
                if (!writable) {
                    throw new IOException("pending write-ahead journal for a read-only file");
                }
                journal.clear();
            }
            return;
        }
        if (!writable) {
            throw new IOException("pending write-ahead journal for a read-only file");
        }
        byte[] id;
        if (record.hasHeader()) {
            if (!recoverHeader(record)) {
                // The header belongs to an older file that used the same name,
                // or it is not a valid header at all.
                journal.clear();
                return;
            }
            id = record.fileId.clone();
        } else {
            try {
                id = fileId();
            } catch (IOException e) {
                // The header itself was torn, and this record does not carry a
                // replacement. There is nothing safe to replay.
                journal.clear();
                return;
            }
            if (!record.matches(id)) {
                // The journal belongs to an older file that used the same name.
                journal.clear();
                return;
            }
        }
        if (id == null) {
            // An empty file has no id for a block record to belong to.
            journal.clear();
            return;
        }
        if (!recordAppliesToFile(record, id, record.hasHeader())) {
            // A malformed or forged journal must never make recovery write at a
            // huge sparse offset, truncate to an arbitrary size, or fail the
            // open with an unbounded exception.
            journal.clear();
            return;
        }
        for (CipherJournal.Block block : record.blocks) {
            writeCipherRange(cipherOffset(block.blockNo, block.data.length), block.data);
        }
        if (record.targetCipherSize >= 0) {
            channel.truncate(record.targetCipherSize);
        }
        channel.force(true);
        dirty = false;
        journalPending = false;
        if (record.targetCipherSize == 0) {
            fileId = null;
            fileIdLoaded = false;
        }
        journal.clear();
    }

    /**
     * Installs the header carried by a journal record, unless the file already
     * has a different valid header (which means the record belongs to an older
     * file that used the same name).
     *
     * @param record the journal record
     * @return {@code true} if the record's header is now in place
     * @throws IOException on filesystem errors
     */
    private boolean recoverHeader(CipherJournal.Record record) throws IOException {
        byte[] replacement = record.header;
        if (replacement.length != Constants.HEADER_LEN) {
            return false;
        }
        byte[] replacementId;
        try {
            replacementId = FileHeader.parse(replacement).id();
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (!Arrays.equals(replacementId, record.fileId)) {
            return false;
        }
        long size = channel.size();
        if (size >= Constants.HEADER_LEN) {
            byte[] existing = readCipherRange(0, Constants.HEADER_LEN);
            if (existing.length == Constants.HEADER_LEN) {
                try {
                    byte[] existingId = FileHeader.parse(existing).id();
                    if (!Arrays.equals(existingId, record.fileId)) {
                        return false;
                    }
                    // The header is already in place; only the size or block
                    // part (if any) still needs to be replayed.
                    fileId = existingId;
                    fileIdLoaded = true;
                    return true;
                } catch (IllegalArgumentException e) {
                    // A torn/corrupt header: repairing it is the point of the
                    // journal record.
                }
            }
        }
        writeCipherRange(0, replacement);
        fileId = replacementId;
        fileIdLoaded = true;
        return true;
    }

    /**
     * Validates a journal record against the file it is about to modify. A
     * record's ciphertext block must authenticate with the file id at its
     * block number, which prevents a forged journal from writing arbitrary data
     * at an attacker-chosen offset. The size fields are bounded so recovery
     * cannot truncate to, or write at, an absurd position.
     *
     * @param record     the journal record
     * @param id         the current file id
     * @param headerSeen whether the record carries a header
     * @return {@code true} if the record can safely be applied
     */
    private boolean recordAppliesToFile(CipherJournal.Record record, byte[] id,
                                         boolean headerSeen) {
        if (record.blocks.isEmpty()) {
            if (record.targetCipherSize < 0) {
                return true;
            }
            if (headerSeen) {
                // A header-only record ends at the header boundary.
                return record.targetCipherSize == Constants.HEADER_LEN;
            }
            try {
                return record.targetCipherSize <= channel.size();
            } catch (IOException e) {
                return false;
            }
        }
        long expectedTarget = -1;
        try {
            for (CipherJournal.Block block : record.blocks) {
                if (block.blockNo < 0 || block.data.length > enc.cipherBS()) {
                    return false;
                }
                // A journalled write always contains real ciphertext. An all-zero
                // block is a sparse hole, not something writeBlock ever journals,
                // so refuse it rather than letting a forged record create a huge
                // sparse extension.
                boolean allZero = true;
                for (byte b : block.data) {
                    if (b != 0) {
                        allZero = false;
                        break;
                    }
                }
                if (allZero) {
                    return false;
                }
                long offset = cipherOffset(block.blockNo, block.data.length);
                if (offset < 0) {
                    return false;
                }
                long end = offset + block.data.length;
                if (end > expectedTarget) {
                    expectedTarget = end;
                }
                enc.decryptBlocks(block.data, 0, block.data.length, block.blockNo, id,
                        blockPlain, 0);
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
        // A batched record always targets the end of its furthest block. A
        // record that only overwrites existing blocks leaves the size alone.
        return record.targetCipherSize < 0 || record.targetCipherSize == expectedTarget;
    }

    /**
     * Returns the ciphertext offset of a journal block, or {@code -1} when the
     * block number would overflow the offset calculation.
     *
     * @param blockNo   the block number
     * @param blockLen  the ciphertext block length
     * @return the offset, or {@code -1}
     */
    private long cipherOffset(long blockNo, int blockLen) {
        if (blockNo < 0) {
            return -1;
        }
        long blockSize = enc.cipherBS();
        if (blockNo > (Long.MAX_VALUE - Constants.HEADER_LEN - blockLen) / blockSize) {
            return -1;
        }
        return enc.blockNoToCipherOff(blockNo);
    }

    /**
     * Starts relocating the journal to follow a renamed ciphertext file.
     *
     * @param newCipherFile the ciphertext file's new path
     * @return the pending move, or {@code null} if there is no journal
     * @throws IOException on filesystem errors
     */
    synchronized CipherJournal.@Nullable Move beginJournalMove(String newCipherFile) throws IOException {
        CipherJournal j = journal;
        return j == null ? null : j.beginMove(newCipherFile);
    }

    /**
     * Completes a journal relocation after the ciphertext file was renamed.
     *
     * @param move the pending move, or {@code null}
     * @throws IOException on filesystem errors
     */
    synchronized void commitJournalMove(CipherJournal.@Nullable Move move) throws IOException {
        CipherJournal j = journal;
        if (j != null && move != null) {
            j.commitMove(move);
        }
    }

    /**
     * Rolls back a journal relocation after the ciphertext rename failed.
     *
     * @param move the pending move, or {@code null}
     * @throws IOException on filesystem errors
     */
    synchronized void rollbackJournalMove(CipherJournal.@Nullable Move move) throws IOException {
        CipherJournal j = journal;
        if (j != null && move != null) {
            j.rollbackMove(move);
        }
    }

    /**
     * Drops the journal and stops journaling future writes. Called when the
     * ciphertext file is deleted: an open handle may still write to the unlinked
     * file, but a journal left at the old name could otherwise be replayed for a
     * different file that later appears there.
     *
     * @throws IOException on filesystem errors
     */
    synchronized void forgetJournal() throws IOException {
        CipherJournal j = journal;
        journal = null;
        if (j != null) {
            j.clear();
        }
    }

    /**
     * Reads and decrypts a whole plaintext block into {@code out[off, ...]}.
     *
     * <p>A block entirely past the end of the file yields a length of zero.
     * Sparse holes decrypt to zero-filled plaintext of the full block size.</p>
     *
     * @param blockNo the block number
     * @param out     the destination buffer
     * @param off     the destination offset
     * @return the number of valid plaintext bytes in the block, or zero past EOF
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code out} is {@code null}
     */
    public synchronized int readBlock(long blockNo, byte[] out, int off) throws IOException {
        Objects.requireNonNull(out, "out");
        if (blockNo < 0 || blockNo > maxPlainSize() / enc.plainBS()) {
            return 0;
        }
        byte[] id = fileId();
        if (id == null) {
            return 0;
        }
        PendingBlock pending = pendingBlocks.get(blockNo);
        if (pending != null) {
            try {
                return enc.decryptBlocks(pending.cipher, 0, pending.cipher.length, blockNo, id,
                        out, off);
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                throw new IOException("corrupt pending block in file", e);
            }
        }
        long pendingEnd = pendingCipherEnd();
        long cipherOffset = enc.blockNoToCipherOff(blockNo);
        if (pendingEnd > channel.size() && cipherOffset >= channel.size()
                && cipherOffset < pendingEnd) {
            // A pending write extends the file past this block, leaving a
            // sparse hole. The block reads back as zeros even though the
            // channel has not grown yet.
            Arrays.fill(out, off, off + (int) enc.plainBS(), (byte) 0);
            return (int) enc.plainBS();
        }
        try {
            return readBlockWithId(blockNo, out, off, id);
        } catch (GeneralSecurityException e) {
            // The cached id may be stale: another handle or process could have
            // truncated the file to empty and rewritten it, minting a new id.
            // Re-read the header once and retry before declaring corruption.
            byte[] reloaded = reloadFileId();
            if (reloaded == null) {
                return 0;
            }
            try {
                return readBlockWithId(blockNo, out, off, reloaded);
            } catch (GeneralSecurityException | IllegalArgumentException e2) {
                throw new IOException("corrupt block in file", e2);
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("corrupt block in file", e);
        }
    }

    /**
     * Reads and decrypts a whole plaintext block using the given file id.
     *
     * @param blockNo the block number
     * @param out     the destination buffer
     * @param off     the destination offset
     * @param id      the file id to authenticate with
     * @return the number of valid plaintext bytes, or zero past EOF
     * @throws IOException on filesystem errors
     * @throws GeneralSecurityException on authentication failure
     */
    private int readBlockWithId(long blockNo, byte[] out, int off, byte[] id)
            throws IOException, GeneralSecurityException {
        long cipherOffset = enc.blockNoToCipherOff(blockNo);
        long cipherSize = channel.size();
        if (cipherOffset >= cipherSize) {
            return 0;
        }
        int len = (int) Math.min(enc.cipherBS(), cipherSize - cipherOffset);
        int read = readCipherRange(cipherOffset, blockCipher, len);
        if (read > 0 && read < enc.cipherBS() && isAllZero(blockCipher, read)) {
            // A zero-extended partial tail is a sparse hole, not a block with
            // an all-zero nonce. Its plaintext is the part before the per-block
            // overhead, and it must read back as zeros instead of failing with
            // an all-zero-nonce error.
            int plainLen = Math.max(read - (int) enc.blockOverhead(), 0);
            Arrays.fill(out, off, off + plainLen, (byte) 0);
            return plainLen;
        }
        return enc.decryptBlocks(blockCipher, 0, read, blockNo, id, out, off);
    }

    /**
     * Encrypts {@code plain[off, off+len)} as block {@code blockNo} and writes
     * it. Writing a block beyond the current end of the file leaves the blocks
     * in between as sparse holes.
     *
     * <p>When a journal is present the encrypted block is buffered and committed
     * together with the other pending blocks by {@link #force(boolean)},
     * {@link #flushPending()} or {@link #close()}. That batches the journal and
     * data fsyncs of a large write instead of paying two fsyncs per block.</p>
     *
     * @param blockNo the block number
     * @param plain   the plaintext buffer
     * @param off     the plaintext offset
     * @param len     the number of plaintext bytes
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plain} is {@code null}
     */
    public synchronized void writeBlock(long blockNo, byte[] plain, int off, int len) throws IOException {
        Objects.requireNonNull(plain, "plain");
        if (!writable) {
            throw new NonWritableChannelException();
        }
        checkPlainRange(blockNo, off, len);
        if (journal == null) {
            writeThrough(blockNo, plain, off, len);
            return;
        }
        enqueue(blockNo, plain, off, len);
        if (pendingBlocks.size() > MAX_PENDING_BLOCKS) {
            commitPending(true);
        }
    }

    /**
     * Encrypts and writes several plaintext blocks as one atomic journal entry.
     * Used for growing a file, where the padded old final block and the new
     * final block must become visible together.
     *
     * @param updates the block updates
     * @throws IOException on filesystem or encryption errors
     */
    void writeBlocks(List<BlockUpdate> updates) throws IOException {
        synchronized (this) {
            if (!writable) {
                throw new NonWritableChannelException();
            }
            for (BlockUpdate update : updates) {
                checkPlainRange(update.blockNo, update.offset, update.length);
            }
            if (journal == null) {
                for (BlockUpdate update : updates) {
                    writeThrough(update.blockNo, update.plain, update.offset, update.length);
                }
                return;
            }
            for (BlockUpdate update : updates) {
                enqueue(update.blockNo, update.plain, update.offset, update.length);
            }
            commitPending(true);
        }
    }

    /**
     * Commits any buffered encrypted blocks, forcing them to storage. Called by
     * an explicit flush so a channel flush still makes its data durable.
     *
     * @throws IOException on filesystem errors
     */
    void flushPending() throws IOException {
        synchronized (this) {
            commitPending(true);
        }
    }

    /**
     * Encrypts one block and writes it directly, without journaling or batching.
     *
     * @param blockNo the block number
     * @param plain   the plaintext buffer
     * @param off     the plaintext offset
     * @param len     the number of plaintext bytes
     * @throws IOException on filesystem or encryption errors
     */
    private void writeThrough(long blockNo, byte[] plain, int off, int len) throws IOException {
        byte[] id = ensureFileId();
        int cipherLen = enc.encryptBlocks(plain, off, len, blockNo, id, blockCipher, 0);
        writeCipherRange(enc.blockNoToCipherOff(blockNo), blockCipher, 0, cipherLen);
    }

    /**
     * Encrypts one block and adds it to the pending batch.
     *
     * @param blockNo the block number
     * @param plain   the plaintext buffer
     * @param off     the plaintext offset
     * @param len     the number of plaintext bytes
     * @throws IOException on filesystem or encryption errors
     */
    private void enqueue(long blockNo, byte[] plain, int off, int len) throws IOException {
        byte[] id = ensureFileId();
        int cipherLen = enc.encryptBlocks(plain, off, len, blockNo, id, blockCipher, 0);
        if (cipherLen > 0) {
            pendingBlocks.put(blockNo,
                    new PendingBlock(blockNo, Arrays.copyOf(blockCipher, cipherLen), len));
        }
    }

    /**
     * Publishes all pending blocks in one journal record, writes them, and
     * optionally forces the data. The journal is only removed by a later force
     * or close, after the data is durable, so a crash can always replay the
     * batch.
     *
     * @param forceData whether to force the written data before returning
     * @throws IOException on filesystem errors
     */
    private void commitPending(boolean forceData) throws IOException {
        if (pendingBlocks.isEmpty()) {
            return;
        }
        byte[] id = fileId();
        if (id == null) {
            pendingBlocks.clear();
            throw new IOException("file header disappeared while writing");
        }
        CipherJournal j = journal;
        List<CipherJournal.Block> blocks = new ArrayList<>(pendingBlocks.size());
        long maxEnd = -1;
        long currentSize = channel.size();
        for (PendingBlock block : pendingBlocks.values()) {
            long offset = enc.blockNoToCipherOff(block.blockNo);
            long end = offset + block.cipher.length;
            if (end > maxEnd) {
                maxEnd = end;
            }
            blocks.add(new CipherJournal.Block(block.blockNo, block.cipher));
        }
        if (j != null) {
            // For an extending batch the target lets recovery finish a torn
            // append; a batch that only overwrites existing blocks leaves the
            // size unchanged.
            long targetSize = maxEnd > currentSize ? maxEnd : -1;
            publishJournal(new CipherJournal.Record(targetSize, id, new byte[0], blocks));
        }
        for (PendingBlock block : pendingBlocks.values()) {
            writeCipherRange(enc.blockNoToCipherOff(block.blockNo), block.cipher, 0,
                    block.cipher.length);
        }
        if (j != null && forceData) {
            channel.force(true);
            dirty = false;
            journalPending = false;
        }
        pendingBlocks.clear();
    }

    /**
     * Pads the final partial plaintext block with zeros up to the full block
     * size and re-encrypts it.
     *
     * <p>A sparse write far beyond the end of the file would otherwise leave
     * the last partial block followed by a hole of zeros; reading that block
     * back then sees the full ciphertext block size (real bytes plus zeros)
     * with the tag at the wrong position, which fails authentication. Padding
     * first turns the partial block into a full block so the hole starts at a
     * clean block boundary. Does nothing for empty or block-aligned files.</p>
     *
     * @throws IOException on filesystem or encryption errors
     */
    public synchronized void zeroPad() throws IOException {
        if (!writable) {
            throw new NonWritableChannelException();
        }
        long size = plainSize();
        if (size == 0 || size % enc.plainBS() == 0) {
            return;
        }
        byte[] id = fileId();
        if (id == null) {
            return;
        }
        long blockNo = (size - 1) / enc.plainBS();
        int len = readBlock(blockNo, blockPlain, 0);
        Arrays.fill(blockPlain, len, (int) enc.plainBS(), (byte) 0);
        writeBlock(blockNo, blockPlain, 0, (int) enc.plainBS());
    }

    /**
     * Truncates the file to {@code newPlainSize} plaintext bytes. Only shrinking
     * and truncation to empty are performed here; growing is handled by
     * {@link SharedCipherFile}.
     *
     * <p>When the new size is block-aligned only the channel is truncated; no
     * block is re-encrypted. Otherwise the final partial block is re-encrypted
     * and written before the stale tail is truncated. A write-ahead journal
     * records both the new block and the target size, so the next open can
     * finish a truncation interrupted by a crash.</p>
     *
     * @param newPlainSize the new plaintext size in bytes
     * @throws IOException on filesystem or encryption errors
     * @throws IllegalArgumentException if {@code newPlainSize} is negative
     */
    public synchronized void truncate(long newPlainSize) throws IOException {
        if (!writable) {
            throw new NonWritableChannelException();
        }
        if (newPlainSize < 0) {
            throw new IllegalArgumentException("negative size: " + newPlainSize);
        }
        if (newPlainSize > maxPlainSize()) {
            throw new IOException("truncate size exceeds maximum plaintext size: " + newPlainSize);
        }
        // Any buffered blocks must be durable before the size changes; otherwise
        // a later commit could resurrect data that this truncation removed.
        commitPending(true);
        if (newPlainSize == 0) {
            // Truncating to empty is handled up front, before the same-size
            // early return below: a torn 1-17 byte header reports a plain size
            // of 0 even though the file still has a partial header, and this
            // must truncate the channel so the file is actually repaired.
            CipherJournal j = journal;
            byte[] id = null;
            if (j != null) {
                try {
                    id = fileId();
                } catch (IOException e) {
                    // A torn header is repaired by the truncation itself.
                }
            }
            if (j != null && id != null) {
                publishJournal(new CipherJournal.Record(-1, 0, id, new byte[0]));
                journalFileTouched = true;
                channel.truncate(0);
                dirty = true;
                fileId = null;
                // Do not cache an empty file: another handle or process may
                // write a new header later, and reads must observe it.
                fileIdLoaded = false;
                channel.force(true);
                dirty = false;
                journalPending = false;
                return;
            }
            channel.truncate(0);
            dirty = true;
            fileId = null;
            // Do not cache an empty file: another handle or process may write
            // a new header later, and reads must observe it.
            fileIdLoaded = false;
            return;
        }
        long oldSize = plainSize();
        if (newPlainSize >= oldSize) {
            return;
        }
        byte[] id = fileId();
        if (id == null) {
            return;
        }
        long blockNo = (newPlainSize - 1) / enc.plainBS();
        long blockStart = blockNo * enc.plainBS();
        int keep = (int) (newPlainSize - blockStart);
        if (keep == enc.plainBS()) {
            // The new size ends on a block boundary, so no block has to be
            // re-encrypted. Just drop the blocks that no longer belong to it.
            long targetSize = enc.blockNoToCipherOff(blockNo + 1);
            CipherJournal j = journal;
            if (j != null) {
                publishJournal(new CipherJournal.Record(-1, targetSize, id, new byte[0]));
                journalFileTouched = true;
            }
            channel.truncate(targetSize);
            dirty = true;
            if (j != null) {
                channel.force(true);
                dirty = false;
                journalPending = false;
            }
            return;
        }
        int len = readBlock(blockNo, blockPlain, 0);
        byte[] truncated = Arrays.copyOf(blockPlain, Math.min(keep, len));
        byte[] cipherBlock = enc.encryptBlock(truncated, blockNo, id);
        long blockCipherOff = enc.blockNoToCipherOff(blockNo);
        long targetSize = blockCipherOff + cipherBlock.length;
        CipherJournal j = journal;
        if (j != null) {
            publishJournal(new CipherJournal.Record(blockNo, targetSize, id, cipherBlock));
        }
        // Write the re-encrypted partial block first, then truncate the stale
        // tail away. Without a journal a crash between the two steps could
        // leave a tail that no longer authenticates; with a journal the next
        // open completes both steps.
        writeCipherRange(blockCipherOff, cipherBlock);
        journalFileTouched = true;
        channel.truncate(targetSize);
        dirty = true;
        if (j != null) {
            channel.force(true);
            dirty = false;
            journalPending = false;
        }
    }

    /**
     * Forces any updates to this file to be written to the storage device. The
     * journal can be removed once the data it describes is durable, so a forced
     * file does not leave a journal for the next reader to trip over.
     *
     * @param metaData whether metadata updates should be forced as well
     * @throws IOException on filesystem errors
     */
    public synchronized void force(boolean metaData) throws IOException {
        commitPending(false);
        channel.force(metaData);
        dirty = false;
        journalPending = false;
        clearJournalIfWritable();
    }

    /**
     * Closes the underlying channel, first forcing any pending content updates
     * to stable storage if the file was opened for writing and has been
     * modified since the last force, then removing any journal record whose
     * data is already durable. Wipes this file's own content-encryption key
     * material and the scratch buffers, which may hold plaintext or ciphertext
     * of the last operation. Calling this method more than once has no effect.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public synchronized void close() throws IOException {
        IOException failure = null;
        try {
            // Commit any batched blocks before the channel is closed. A failure
            // here is reported after the channel and keys have been released.
            if (writable && channel.isOpen()) {
                commitPending(false);
            }
            // fsync writable files only when a write since the last force would
            // otherwise be lost by a power loss after close(). Read-only files,
            // and files whose updates were already forced, have nothing to
            // force, so the caller does not pay a redundant fsync on every
            // close.
            if (dirty && writable && channel.isOpen()) {
                channel.force(true);
                dirty = false;
                // The force succeeded, so every journalled change is durable.
                journalPending = false;
            }
            if (writable) {
                try {
                    clearJournalIfWritable();
                } catch (IOException e) {
                    failure = e;
                }
            }
        } finally {
            try {
                channel.close();
            } finally {
                enc.wipe();
                Arrays.fill(blockCipher, (byte) 0);
                Arrays.fill(blockPlain, (byte) 0);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    /**
     * Removes the journal record if this file is writable. The record is only
     * dropped after the data it describes has been forced, so leaving it in
     * place is also safe; this just avoids making a later read-only open fail.
     *
     * @throws IOException on filesystem errors
     */
    private void clearJournalIfWritable() throws IOException {
        CipherJournal j = journal;
        if (writable && j != null && (!journalPending || !journalFileTouched)) {
            // Either the data is durable, or the failed write never touched the
            // main file. In both cases the record has nothing left to recover.
            j.clear();
            journalPending = false;
            journalFileTouched = false;
        }
    }

    /**
     * Publishes a new journal record before modifying the main file.
     *
     * @param record the record to publish
     * @throws IOException on filesystem errors
     */
    private void publishJournal(CipherJournal.Record record) throws IOException {
        CipherJournal j = journal;
        if (j != null) {
            j.write(record);
            journalPending = true;
            journalFileTouched = false;
        }
    }

    /**
     * Loads the file id from the header if it has not been loaded yet.
     *
     * @return the 16-byte file id, or {@code null} if the file is empty
     * @throws IOException on filesystem errors or a corrupt header
     */
    private byte @Nullable [] loadFileId() throws IOException {
        if (!fileIdLoaded) {
            long size = channel.size();
            if (size < Constants.HEADER_LEN) {
                // Do not cache an empty file. Another handle or process may
                // mint a header at any time, so the size has to be re-checked
                // on the next call. A file shorter than a header is a torn
                // first write and carries no usable content, so it reads as
                // empty; a later write mints a fresh header in its place.
                fileId = null;
                return null;
            }
            byte[] hdr = readCipherRange(0, Constants.HEADER_LEN);
            if (hdr.length < Constants.HEADER_LEN) {
                throw new IOException("corrupt file header");
            }
            try {
                fileId = FileHeader.parse(hdr).id();
            } catch (IllegalArgumentException e) {
                throw new IOException("corrupt file header", e);
            }
            fileIdLoaded = true;
        }
        return fileId;
    }

    /**
     * Forces a fresh read of the file header, discarding any cached id.
     *
     * @return the current 16-byte file id, or {@code null} if the file is empty
     * @throws IOException on filesystem errors or a corrupt header
     */
    private byte @Nullable [] reloadFileId() throws IOException {
        fileId = null;
        fileIdLoaded = false;
        return loadFileId();
    }

    /**
     * Returns the file id, minting and writing a fresh header if the file is
     * empty.
     *
     * @return the 16-byte file id
     * @throws IOException on filesystem errors
     */
    private byte[] ensureFileId() throws IOException {
        byte[] id = loadFileId();
        if (id == null) {
            // The file looked empty, but another handle may have minted a header
            // between loadFileId's size check and here. Re-check the size and,
            // if a complete header appeared, adopt it instead of overwriting it
            // with a fresh one (which would make every block written so far
            // unreadable). A partial header is a torn first write; it carries no
            // usable content and is replaced below.
            long size = channel.size();
            if (size >= Constants.HEADER_LEN) {
                fileIdLoaded = false;
                id = loadFileId();
                if (id == null) {
                    throw new IOException("file header disappeared while writing");
                }
                return id;
            }
            // The file is empty (or has a torn header): mint a fresh header.
            FileHeader h = FileHeader.random();
            byte[] header = h.pack();
            CipherJournal j = journal;
            if (j != null) {
                // Publish the header before writing it so a crash between the
                // two leaves a recoverable journal instead of a corrupt file.
                publishJournal(new CipherJournal.Record(-1, Constants.HEADER_LEN, h.id(),
                        new byte[0], header));
            }
            writeCipherRange(0, header);
            fileId = h.id();
            fileIdLoaded = true;
            id = fileId;
            if (j != null) {
                // The header must be durable before the next journal record
                // replaces this one; after that record a torn header would no
                // longer be recoverable.
                channel.force(true);
                dirty = false;
                journalPending = false;
                j.clear();
            }
        }
        return id;
    }

    /**
     * Returns whether the first {@code length} bytes of an array are all zero.
     *
     * @param data   the array
     * @param length the number of bytes to inspect
     * @return {@code true} if every inspected byte is zero
     */
    private static boolean isAllZero(byte[] data, int length) {
        for (int i = 0; i < length; i++) {
            if (data[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Reads up to {@code length} ciphertext bytes into a new array.
     *
     * @param offset the ciphertext start offset
     * @param length the maximum number of bytes to read
     * @return the bytes read, possibly fewer than requested
     * @throws IOException on filesystem errors
     */
    private byte[] readCipherRange(long offset, int length) throws IOException {
        byte[] buf = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(buf);
        channel.position(offset);
        while (bb.hasRemaining()) {
            int n = channel.read(bb);
            if (n < 0) {
                break;
            }
        }
        if (bb.position() == 0) {
            return new byte[0];
        }
        return Arrays.copyOf(buf, bb.position());
    }

    /**
     * Reads up to {@code length} ciphertext bytes into {@code buf} and returns
     * the byte count.
     *
     * @param offset the ciphertext start offset
     * @param buf    the destination buffer
     * @param length the maximum number of bytes to read
     * @return the number of bytes read
     * @throws IOException on filesystem errors
     */
    private int readCipherRange(long offset, byte[] buf, int length) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(buf, 0, length);
        channel.position(offset);
        while (bb.hasRemaining()) {
            int n = channel.read(bb);
            if (n < 0) {
                break;
            }
        }
        return bb.position();
    }

    /**
     * Writes a range of {@code data} at the ciphertext {@code offset}.
     *
     * @param offset  the ciphertext start offset
     * @param data    the data buffer
     * @param dataOff the offset within {@code data}
     * @param dataLen the number of bytes to write
     * @throws IOException on filesystem errors
     */
    private void writeCipherRange(long offset, byte[] data, int dataOff, int dataLen) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(data, dataOff, dataLen);
        channel.position(offset);
        int start = bb.position();
        try {
            while (bb.hasRemaining()) {
                if (channel.write(bb) > 0) {
                    journalFileTouched = true;
                }
            }
        } catch (IOException e) {
            if (bb.position() > start) {
                journalFileTouched = true;
            }
            throw e;
        }
        dirty = true;
    }

    /**
     * Writes all of {@code data} at the ciphertext {@code offset}.
     *
     * @param offset the ciphertext start offset
     * @param data   the data to write
     * @throws IOException on filesystem errors
     */
    private void writeCipherRange(long offset, byte[] data) throws IOException {
        writeCipherRange(offset, data, 0, data.length);
    }
}
