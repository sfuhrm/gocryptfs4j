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
import java.util.Arrays;
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

    /** The file id from the header, or {@code null} for an empty file. */
    private byte @Nullable [] fileId;

    /** Whether the file id has been loaded from the header. */
    private boolean fileIdLoaded;

    /** Whether the file has been modified since the last {@link #force(boolean)}. */
    private boolean dirty;

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
        return enc.cipherSizeToPlainSize(channel.size());
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
        byte[] id = fileId();
        if (!record.matches(id)) {
            // The journal belongs to an older file that used the same name.
            journal.clear();
            return;
        }
        if (record.blockNo >= 0 && record.block.length > 0) {
            writeCipherRange(enc.blockNoToCipherOff(record.blockNo), record.block);
        }
        if (record.targetCipherSize >= 0) {
            channel.truncate(record.targetCipherSize);
        }
        channel.force(true);
        dirty = false;
        if (record.targetCipherSize == 0) {
            fileId = null;
            fileIdLoaded = false;
        }
        journal.clear();
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
        byte[] id = fileId();
        if (id == null) {
            return 0;
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
        return enc.decryptBlocks(blockCipher, 0, read, blockNo, id, out, off);
    }

    /**
     * Encrypts {@code plain[off, off+len)} as block {@code blockNo} and writes
     * it. Writing a block beyond the current end of the file leaves the blocks
     * in between as sparse holes.
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
        byte[] id = ensureFileId();
        int cipherLen = enc.encryptBlocks(plain, off, len, blockNo, id, blockCipher, 0);
        long cipherOffset = enc.blockNoToCipherOff(blockNo);
        CipherJournal j = journal;
        if (j != null && cipherOffset < channel.size()) {
            j.write(new CipherJournal.Record(blockNo, -1, id,
                    Arrays.copyOf(blockCipher, cipherLen)));
            writeCipherRange(cipherOffset, blockCipher, 0, cipherLen);
            channel.force(true);
            dirty = false;
            j.clear();
        } else {
            writeCipherRange(cipherOffset, blockCipher, 0, cipherLen);
        }
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
                j.write(new CipherJournal.Record(-1, 0, id, new byte[0]));
                channel.truncate(0);
                dirty = true;
                fileId = null;
                // Do not cache an empty file: another handle or process may
                // write a new header later, and reads must observe it.
                fileIdLoaded = false;
                channel.force(true);
                dirty = false;
                j.clear();
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
                j.write(new CipherJournal.Record(-1, targetSize, id, new byte[0]));
            }
            channel.truncate(targetSize);
            dirty = true;
            if (j != null) {
                channel.force(true);
                dirty = false;
                j.clear();
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
            j.write(new CipherJournal.Record(blockNo, targetSize, id, cipherBlock));
        }
        // Write the re-encrypted partial block first, then truncate the stale
        // tail away. Without a journal a crash between the two steps could
        // leave a tail that no longer authenticates; with a journal the next
        // open completes both steps.
        writeCipherRange(blockCipherOff, cipherBlock);
        channel.truncate(targetSize);
        dirty = true;
        if (j != null) {
            channel.force(true);
            dirty = false;
            j.clear();
        }
    }

    /**
     * Forces any updates to this file to be written to the storage device.
     *
     * @param metaData whether metadata updates should be forced as well
     * @throws IOException on filesystem errors
     */
    public synchronized void force(boolean metaData) throws IOException {
        channel.force(metaData);
        dirty = false;
    }

    /**
     * Closes the underlying channel, first forcing any pending content updates
     * to stable storage if the file was opened for writing and has been
     * modified since the last force, and wipes this file's own
     * content-encryption key material and the scratch buffers, which may hold
     * plaintext or ciphertext of the last operation. Calling this method more
     * than once has no effect.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public synchronized void close() throws IOException {
        try {
            // fsync writable files only when a write since the last force would
            // otherwise be lost by a power loss after close(). Read-only files,
            // and files whose updates were already forced, have nothing to
            // force, so the caller does not pay a redundant fsync on every
            // close.
            if (dirty && writable && channel.isOpen()) {
                channel.force(true);
                dirty = false;
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
            if (size == 0) {
                // Do not cache an empty file. Another handle or process may
                // mint a header at any time, so the size has to be re-checked
                // on the next call.
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
            // if a header appeared, adopt it instead of overwriting it with a
            // fresh one (which would make every block written so far unreadable).
            if (channel.size() > 0) {
                fileIdLoaded = false;
                id = loadFileId();
                if (id == null) {
                    throw new IOException("file header disappeared while writing");
                }
                return id;
            }
            // The file is empty (or was truncated to empty): mint a fresh header.
            FileHeader h = FileHeader.random();
            writeCipherRange(0, h.pack());
            fileId = h.id();
            fileIdLoaded = true;
            id = fileId;
        }
        return id;
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
        while (bb.hasRemaining()) {
            channel.write(bb);
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
