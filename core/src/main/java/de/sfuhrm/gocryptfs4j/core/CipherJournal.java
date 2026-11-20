package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A small write-ahead journal for a single encrypted file.
 *
 * <p>The ciphertext format has no atomic in-place block update. Before a block
 * is written (including an append), a file is shrunk, or a new file header is
 * installed, the new ciphertext and target size are published durably in a
 * hidden sibling journal. After the main file has been written and forced, the
 * journal can be removed. If the process dies in between, the next open replays
 * the journal before any read or write.</p>
 *
 * <p>Journal files use the reserved {@code .gocryptfs} prefix and are hidden
 * from directory listings. They are only left behind after a crash and are
 * replayed and removed by the next writable open, which holds the cipher root
 * lock. A read-only open never replays, modifies, or removes a journal; if one
 * is present it fails instead, so a reader can never roll back a live writer's
 * work.</p>
 */
final class CipherJournal {

    /** Journal file format magic. */
    private static final int MAGIC = 0x47434657;

    /** Current journal file format version (supports multiple block updates). */
    private static final byte VERSION = 3;

    /** Journal format version 2, which carries a single block and an optional header. */
    private static final byte VERSION_SINGLE = 2;

    /** Legacy journal file format version without a header field. */
    private static final byte VERSION_LEGACY = 1;

    /** Maximum accepted ciphertext block length in a journal record. */
    private static final int MAX_BLOCK_LEN = 1 << 20;

    /** Maximum number of block updates accepted in one journal record. */
    private static final int MAX_BLOCK_COUNT = 1024;

    /**
     * Maximum accepted journal size. A batched record carries at most
     * {@link #MAX_BLOCK_COUNT} ordinary ciphertext blocks, so this leaves plenty
     * of room while still bounding a hostile journal file.
     */
    private static final int MAX_JOURNAL_LEN = 8 << 20;

    /** Prefix of the hidden journal file name. */
    private static final String NAME_PREFIX = Constants.INTERNAL_NAME_PREFIX + "-wal-";

    /** The store holding the journal. */
    private final CipherStore store;

    /**
     * The hidden journal path. A rename moves it to follow the cipher file, so
     * it is not final; all access is serialized by the owning {@link CipherFile}
     * or by the rename operation's channel lock.
     */
    private volatile String journalName;

    /**
     * The journal path used by releases that hashed the full ciphertext path.
     * It is only read (and removed), never written, for one release so a
     * pending journal from an older version is still replayed.
     */
    private volatile String legacyJournalName;

    /**
     * Creates a journal for the given ciphertext file.
     *
     * @param store      the ciphertext store
     * @param cipherFile the ciphertext file whose blocks are journalled
     * @throws NullPointerException if an argument is {@code null}
     */
    CipherJournal(CipherStore store, String cipherFile) {
        this.store = Objects.requireNonNull(store, "store");
        this.journalName = journalName(cipherFile);
        this.legacyJournalName = legacyJournalName(cipherFile);
    }

    /**
     * Returns the hidden journal path for a ciphertext file.
     *
     * <p>Only the ciphertext base name is hashed. The journal lives in the same
     * directory, where that name is unique, so moving the vault to another path
     * or renaming a directory leaves the journal name unchanged.</p>
     *
     * @param cipherFile the ciphertext file whose blocks are journalled
     * @return the journal path
     */
    static String journalName(String cipherFile) {
        Objects.requireNonNull(cipherFile, "cipherFile");
        int slash = Math.max(cipherFile.lastIndexOf('/'), cipherFile.lastIndexOf('\\'));
        String parent = slash < 0 ? "" : cipherFile.substring(0, slash + 1);
        String base = cipherFile.substring(slash + 1);
        return parent + NAME_PREFIX + hash(base);
    }

    /**
     * Returns the legacy journal path that hashed the full ciphertext path.
     *
     * <p>This format is still accepted for one release so an upgrade can replay
     * a journal left by the previous version. New journals never use it.</p>
     *
     * @param cipherFile the ciphertext file whose blocks are journalled
     * @return the legacy journal path
     */
    static String legacyJournalName(String cipherFile) {
        Objects.requireNonNull(cipherFile, "cipherFile");
        int slash = Math.max(cipherFile.lastIndexOf('/'), cipherFile.lastIndexOf('\\'));
        String parent = slash < 0 ? "" : cipherFile.substring(0, slash + 1);
        return parent + NAME_PREFIX + hash(cipherFile);
    }

    /**
     * Returns whether a file name has the journal name prefix.
     *
     * @param name the file name to test
     * @return {@code true} if the name is a journal file name
     */
    static boolean isJournalName(String name) {
        return name.startsWith(NAME_PREFIX);
    }

    /**
     * Returns the hidden journal path.
     *
     * @return the journal path
     */
    String name() {
        return journalName;
    }

    /**
     * Reads the current journal record, or {@code null} if there is none or it
     * does not parse. This never modifies the store, so it is safe to call on a
     * read-only backend; use {@link #exists()} to distinguish an unparseable
     * journal from an absent one.
     *
     * @return the record, or {@code null}
     * @throws IOException on filesystem errors
     */
    @Nullable Record read() throws IOException {
        Record record = read(journalName);
        if (record != null || journalName.equals(legacyJournalName)
                || existsAt(journalName)) {
            // A present but unparseable primary journal wins over an older
            // legacy one; a writable open discards both.
            return record;
        }
        return read(legacyJournalName);
    }

    /**
     * Reads one journal path without falling back.
     *
     * @param name the journal path
     * @return the record, or {@code null} if it is absent or invalid
     * @throws IOException on filesystem errors
     */
    private @Nullable Record read(String name) throws IOException {
        byte[] data;
        try {
            CipherNode node = store.stat(name);
            if (!node.isRegularFile() || node.size() > MAX_JOURNAL_LEN) {
                // Treat an oversized or non-regular journal as unparseable
                // instead of letting it make the file open fail; a writable
                // open discards it.
                return null;
            }
            data = store.readSmall(name, MAX_JOURNAL_LEN);
        } catch (NoSuchFileException e) {
            return null;
        }
        return parse(data);
    }

    /**
     * Returns whether a journal file is present, whether or not it parses.
     *
     * @return {@code true} if a journal file exists
     * @throws IOException on filesystem errors
     */
    boolean exists() throws IOException {
        return existsAt(journalName)
                || (!journalName.equals(legacyJournalName) && existsAt(legacyJournalName));
    }

    /**
     * Returns whether one journal path exists.
     *
     * @param name the journal path
     * @return {@code true} if the file exists
     * @throws IOException on filesystem errors
     */
    private boolean existsAt(String name) throws IOException {
        try {
            store.stat(name);
            return true;
        } catch (NoSuchFileException e) {
            return false;
        }
    }

    /**
     * Atomically publishes a journal record.
     *
     * @param record the record to write
     * @throws IOException on filesystem errors
     */
    void write(Record record) throws IOException {
        store.writeJournal(journalName, record.encode());
        if (!journalName.equals(legacyJournalName)) {
            deleteIfExists(legacyJournalName);
        }
    }

    /**
     * Removes the journal, if present.
     *
     * @throws IOException on filesystem errors
     */
    void clear() throws IOException {
        deleteIfExists(journalName);
        if (!journalName.equals(legacyJournalName)) {
            deleteIfExists(legacyJournalName);
        }
    }

    /**
     * Starts relocating this journal to the path of a renamed ciphertext file.
     *
     * <p>The journal is copied to its new name before the caller renames the
     * cipher file, and the old copy is kept until the rename succeeds. A crash
     * before the cipher-file rename therefore still leaves a valid journal at
     * the old path, and a crash after it leaves one at the new path.</p>
     *
     * @param newCipherFile the ciphertext file's new path
     * @return the pending move, or {@code null} if the journal name is unchanged
     * @throws IOException on filesystem errors
     */
    @Nullable Move beginMove(String newCipherFile) throws IOException {
        String oldName = journalName;
        String oldLegacy = legacyJournalName;
        String newName = journalName(newCipherFile);
        String newLegacy = legacyJournalName(newCipherFile);
        if (newName.equals(oldName) && newLegacy.equals(oldLegacy)) {
            return null;
        }
        byte[] data = readIfExists(oldName);
        if (data == null && !oldLegacy.equals(oldName)) {
            data = readIfExists(oldLegacy);
        }
        byte[] replaced = readIfExists(newName);
        boolean copied = false;
        if (data != null) {
            try {
                store.writeSmall(newName, data, true);
                copied = true;
            } catch (NoSuchFileException e) {
                // A directory rename moves the journal into a directory that
                // does not exist yet. Copy it after the cipher file has moved.
            }
        }
        return new Move(oldName, oldLegacy, newName, newLegacy,
                data, replaced, copied);
    }

    /**
     * Completes a move started by {@link #beginMove(String)}.
     *
     * @param move the pending move
     * @throws IOException on filesystem errors
     */
    void commitMove(Move move) throws IOException {
        journalName = move.newName;
        legacyJournalName = move.newLegacy;
        if (move.data != null) {
            if (!move.copied) {
                store.writeSmall(move.newName, move.data, true);
            }
            if (!move.oldName.equals(move.newName)) {
                deleteIfExists(move.oldName);
            }
            if (!move.oldLegacy.equals(move.oldName)
                    && !move.oldLegacy.equals(move.newName)) {
                deleteIfExists(move.oldLegacy);
            }
            if (!move.newLegacy.equals(move.newName)) {
                // A legacy journal at the target belonged to the entry that the
                // rename replaced, not to the moved file.
                deleteIfExists(move.newLegacy);
            }
        } else {
            // The source had no pending journal. Journals at the target
            // belonged to the entry that the rename replaced, so they must not
            // be replayed for the new file.
            deleteIfExists(move.newName);
            if (!move.newLegacy.equals(move.newName)) {
                deleteIfExists(move.newLegacy);
            }
        }
    }

    /**
     * Rolls back a move started by {@link #beginMove(String)} after the
     * cipher-file rename failed.
     *
     * @param move the pending move
     * @throws IOException on filesystem errors
     */
    void rollbackMove(Move move) throws IOException {
        if (move.data == null || !move.copied) {
            return;
        }
        if (move.replaced != null) {
            store.writeSmall(move.newName, move.replaced, true);
        } else {
            deleteIfExists(move.newName);
        }
    }

    /**
     * Reads a journal file without failing when it is absent.
     *
     * @param name the journal path
     * @return the bytes, or {@code null} if there is no file
     * @throws IOException on filesystem errors
     */
    private byte @Nullable [] readIfExists(String name) throws IOException {
        try {
            return store.readSmall(name, MAX_JOURNAL_LEN);
        } catch (NoSuchFileException e) {
            return null;
        }
    }

    /**
     * Deletes a journal file without failing when it is absent.
     *
     * @param name the journal path
     * @throws IOException on filesystem errors
     */
    private void deleteIfExists(String name) throws IOException {
        try {
            store.delete(name);
        } catch (NoSuchFileException e) {
            // Already absent.
        }
    }

    /**
     * One pending journal relocation.
     */
    static final class Move {

        /** The journal path before the rename. */
        private final String oldName;

        /** The legacy journal path before the rename. */
        private final String oldLegacy;

        /** The journal path after the rename. */
        private final String newName;

        /** The legacy journal path after the rename. */
        private final String newLegacy;

        /** The journal contents, or {@code null} if there was no journal. */
        private final byte @Nullable [] data;

        /** The target's previous journal contents, or {@code null}. */
        private final byte @Nullable [] replaced;

        /** Whether the journal was already copied to the new path. */
        private final boolean copied;

        /**
         * Creates a pending move.
         *
         * @param oldName   the old journal path
         * @param oldLegacy the old legacy journal path
         * @param newName   the new journal path
         * @param newLegacy the new legacy journal path
         * @param data      the journal contents, or {@code null}
         * @param replaced  the target's previous contents, or {@code null}
         * @param copied    whether the journal was already copied
         */
        private Move(String oldName, String oldLegacy, String newName, String newLegacy,
                     byte @Nullable [] data, byte @Nullable [] replaced, boolean copied) {
            this.oldName = oldName;
            this.oldLegacy = oldLegacy;
            this.newName = newName;
            this.newLegacy = newLegacy;
            this.data = data;
            this.replaced = replaced;
            this.copied = copied;
        }
    }

    /**
     * Parses a journal record.
     *
     * @param data the raw journal bytes
     * @return the parsed record, or {@code null} if the bytes are invalid
     */
    private static @Nullable Record parse(byte[] data) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            if (in.readInt() != MAGIC) {
                return null;
            }
            int version = in.readUnsignedByte();
            if (version == VERSION) {
                return parseMultiBlock(in);
            }
            if (version != VERSION_SINGLE && version != VERSION_LEGACY) {
                return null;
            }
            // Versions 1 and 2 carry at most one block update.
            long blockNo = in.readLong();
            long targetCipherSize = in.readLong();
            byte[] fileId = new byte[Constants.HEADER_ID_LEN];
            in.readFully(fileId);
            byte[] header = new byte[0];
            if (version >= VERSION_SINGLE) {
                int headerLength = in.readInt();
                if (headerLength != 0 && headerLength != Constants.HEADER_LEN) {
                    return null;
                }
                header = new byte[headerLength];
                in.readFully(header);
            }
            int length = in.readInt();
            if (length < 0 || length > MAX_BLOCK_LEN) {
                return null;
            }
            byte[] block = new byte[length];
            in.readFully(block);
            if (in.available() != 0) {
                return null;
            }
            if (blockNo < -1 || targetCipherSize < -1) {
                return null;
            }
            List<Block> blocks = blockNo >= 0 && length > 0
                    ? Collections.singletonList(new Block(blockNo, block))
                    : Collections.<Block>emptyList();
            return new Record(targetCipherSize, fileId, header, blocks);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Parses the multi-block journal format used for batched writes and atomic
     * file growth.
     *
     * @param in the journal stream positioned after the version byte
     * @return the parsed record, or {@code null} if the bytes are invalid
     * @throws IOException if the record cannot be read
     */
    private static @Nullable Record parseMultiBlock(DataInputStream in) throws IOException {
        long targetCipherSize = in.readLong();
        byte[] fileId = new byte[Constants.HEADER_ID_LEN];
        in.readFully(fileId);
        int headerLength = in.readInt();
        if (headerLength != 0 && headerLength != Constants.HEADER_LEN) {
            return null;
        }
        byte[] header = new byte[headerLength];
        in.readFully(header);
        int blockCount = in.readInt();
        if (blockCount < 0 || blockCount > MAX_BLOCK_COUNT) {
            return null;
        }
        List<Block> blocks = new ArrayList<>(blockCount);
        for (int i = 0; i < blockCount; i++) {
            long blockNo = in.readLong();
            int length = in.readInt();
            if (blockNo < 0 || length <= 0 || length > MAX_BLOCK_LEN) {
                return null;
            }
            byte[] block = new byte[length];
            in.readFully(block);
            blocks.add(new Block(blockNo, block));
        }
        if (in.available() != 0) {
            return null;
        }
        if (targetCipherSize < -1) {
            return null;
        }
        return new Record(targetCipherSize, fileId, header, blocks);
    }

    /**
     * Returns a stable, bounded file-name component for the given cipher path.
     *
     * @param cipherFile the ciphertext file path
     * @return a hexadecimal SHA-256 digest
     */
    private static String hash(String cipherFile) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(cipherFile.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                out.append(Character.forDigit((b >>> 4) & 0x0F, 16));
                out.append(Character.forDigit(b & 0x0F, 16));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * One journalled update, possibly covering several blocks so that a batch
     * or an atomic grow can be replayed as a single unit.
     */
    static final class Record {

        /** The target ciphertext size, or {@code -1} to leave the size unchanged. */
        final long targetCipherSize;

        /** The file id the record belongs to. */
        final byte[] fileId;

        /** A new file header to install before the blocks, or an empty array. */
        final byte[] header;

        /** The block updates to apply, in order. */
        final List<Block> blocks;

        /**
         * Creates a record without a header.
         *
         * @param blockNo          the block number, or {@code -1}
         * @param targetCipherSize the target ciphertext size, or {@code -1}
         * @param fileId           the file id
         * @param block            the new ciphertext block
         */
        Record(long blockNo, long targetCipherSize, byte[] fileId, byte[] block) {
            this(blockNo, targetCipherSize, fileId, block, new byte[0]);
        }

        /**
         * Creates a single-block record.
         *
         * @param blockNo          the block number, or {@code -1}
         * @param targetCipherSize the target ciphertext size, or {@code -1}
         * @param fileId           the file id
         * @param block            the new ciphertext block
         * @param header           a new file header, or an empty array
         */
        Record(long blockNo, long targetCipherSize, byte[] fileId, byte[] block,
               byte[] header) {
            this(targetCipherSize, fileId, header,
                    blockNo >= 0 && block.length > 0
                            ? Collections.singletonList(new Block(blockNo, block))
                            : Collections.<Block>emptyList());
        }

        /**
         * Creates a multi-block record.
         *
         * @param targetCipherSize the target ciphertext size, or {@code -1}
         * @param fileId           the file id
         * @param header           a new file header, or an empty array
         * @param blocks           the block updates
         */
        Record(long targetCipherSize, byte[] fileId, byte[] header, List<Block> blocks) {
            this.targetCipherSize = targetCipherSize;
            this.fileId = fileId.clone();
            this.header = header.clone();
            this.blocks = new ArrayList<>(blocks.size());
            for (Block block : blocks) {
                this.blocks.add(new Block(block.blockNo, block.data));
            }
        }

        /**
         * Returns whether this record installs a file header.
         *
         * @return {@code true} if a header is present
         */
        boolean hasHeader() {
            return header.length != 0;
        }

        /**
         * Returns whether this record matches the given file id.
         *
         * @param id the current file id, or {@code null}
         * @return {@code true} if the record applies to that file
         */
        boolean matches(byte @Nullable [] id) {
            return id != null && Arrays.equals(fileId, id);
        }

        /**
         * Encodes this record for storage.
         *
         * @return the encoded bytes
         * @throws IOException if the record cannot be encoded
         */
        byte[] encode() throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(bytes)) {
                out.writeInt(MAGIC);
                out.writeByte(VERSION);
                out.writeLong(targetCipherSize);
                out.write(fileId);
                out.writeInt(header.length);
                out.write(header);
                out.writeInt(blocks.size());
                for (Block block : blocks) {
                    out.writeLong(block.blockNo);
                    out.writeInt(block.data.length);
                    out.write(block.data);
                }
            }
            return bytes.toByteArray();
        }
    }

    /**
     * One ciphertext block update inside a {@link Record}.
     */
    static final class Block {

        /** The block number. */
        final long blockNo;

        /** The new ciphertext block. */
        final byte[] data;

        /**
         * Creates a block update.
         *
         * @param blockNo the block number
         * @param data    the ciphertext block
         */
        Block(long blockNo, byte[] data) {
            this.blockNo = blockNo;
            this.data = data.clone();
        }
    }
}
