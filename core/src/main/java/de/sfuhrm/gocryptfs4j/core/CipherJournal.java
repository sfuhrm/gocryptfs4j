package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
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
import java.util.Arrays;
import java.util.Objects;

/**
 * A small write-ahead journal for a single encrypted file.
 *
 * <p>The ciphertext format has no atomic in-place block update. Before a block
 * is overwritten (or a file is shrunk), the new ciphertext and target size are
 * published atomically in a hidden sibling journal. After the main file has
 * been written and forced, the journal is removed. If the process dies in
 * between, the next open replays the journal before any read or write.</p>
 *
 * <p>Journal files use the reserved {@code .gocryptfs} prefix and are hidden
 * from directory listings. They are only left behind after a crash and are
 * removed as soon as the file is opened again.</p>
 */
final class CipherJournal {

    /** Journal file format magic. */
    private static final int MAGIC = 0x47434657;

    /** Journal file format version. */
    private static final byte VERSION = 1;

    /** Maximum accepted ciphertext block length in a journal record. */
    private static final int MAX_BLOCK_LEN = 1 << 20;

    /** Prefix of the hidden journal file name. */
    private static final String NAME_PREFIX = Constants.INTERNAL_NAME_PREFIX + "-wal-";

    /** The store holding the journal. */
    private final CipherStore store;

    /** The hidden journal path. */
    private final String journalName;

    /**
     * Creates a journal for the given ciphertext file.
     *
     * @param store      the ciphertext store
     * @param cipherFile the ciphertext file whose blocks are journalled
     * @throws NullPointerException if an argument is {@code null}
     */
    CipherJournal(CipherStore store, String cipherFile) {
        this.store = Objects.requireNonNull(store, "store");
        Objects.requireNonNull(cipherFile, "cipherFile");
        int slash = Math.max(cipherFile.lastIndexOf('/'), cipherFile.lastIndexOf('\\'));
        String parent = slash < 0 ? "" : cipherFile.substring(0, slash + 1);
        this.journalName = parent + NAME_PREFIX + hash(cipherFile);
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
     * Reads the current journal record, or {@code null} if there is none. An
     * unparseable record is removed and treated as absent.
     *
     * @return the record, or {@code null}
     * @throws IOException on filesystem errors
     */
    @Nullable Record read() throws IOException {
        byte[] data;
        try {
            store.stat(journalName);
            data = store.readSmall(journalName, MAX_BLOCK_LEN + 64);
        } catch (NoSuchFileException e) {
            return null;
        }
        Record record = parse(data);
        if (record == null) {
            clear();
        }
        return record;
    }

    /**
     * Atomically publishes a journal record.
     *
     * @param record the record to write
     * @throws IOException on filesystem errors
     */
    void write(Record record) throws IOException {
        store.writeSmall(journalName, record.encode(), true);
    }

    /**
     * Removes the journal, if present.
     *
     * @throws IOException on filesystem errors
     */
    void clear() throws IOException {
        try {
            store.delete(journalName);
        } catch (NoSuchFileException e) {
            // Already absent.
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
            if (in.readInt() != MAGIC || in.readByte() != VERSION) {
                return null;
            }
            long blockNo = in.readLong();
            long targetCipherSize = in.readLong();
            byte[] fileId = new byte[Constants.HEADER_ID_LEN];
            in.readFully(fileId);
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
            return new Record(blockNo, targetCipherSize, fileId, block);
        } catch (IOException | RuntimeException e) {
            return null;
        }
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
     * One journalled update.
     */
    static final class Record {

        /** The block to rewrite, or {@code -1} for a truncate-only record. */
        final long blockNo;

        /** The target ciphertext size, or {@code -1} to leave the size unchanged. */
        final long targetCipherSize;

        /** The file id the record belongs to. */
        final byte[] fileId;

        /** The new ciphertext block, possibly empty. */
        final byte[] block;

        /**
         * Creates a record.
         *
         * @param blockNo          the block number, or {@code -1}
         * @param targetCipherSize the target ciphertext size, or {@code -1}
         * @param fileId           the file id
         * @param block            the new ciphertext block
         */
        Record(long blockNo, long targetCipherSize, byte[] fileId, byte[] block) {
            this.blockNo = blockNo;
            this.targetCipherSize = targetCipherSize;
            this.fileId = fileId.clone();
            this.block = block.clone();
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
                out.writeLong(blockNo);
                out.writeLong(targetCipherSize);
                out.write(fileId);
                out.writeInt(block.length);
                out.write(block);
            }
            return bytes.toByteArray();
        }
    }
}
