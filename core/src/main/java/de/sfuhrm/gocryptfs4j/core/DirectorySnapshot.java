package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.store.CipherNode;

import java.io.IOException;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An immutable snapshot of a ciphertext directory listing.
 *
 * <p>Snapshots are produced by {@link GocryptFs#snapshotDirectory(String)} and
 * compared with {@link #changesSince(DirectorySnapshot)}. The comparison uses
 * the ciphertext names and their metadata directly, so only the names of
 * entries that actually appeared, disappeared or changed are decrypted. A
 * polling watcher can therefore skip the EME work for an unchanged
 * directory.</p>
 */
public final class DirectorySnapshot {

    /** The directory manager used to decrypt the names of changed entries. */
    private final DirectoryManager directoryManager;

    /** The ciphertext path of the snapshotted directory. */
    private final String cipherDir;

    /** The entries, keyed by their ciphertext storage name. */
    private final Map<String, Entry> entries;

    /**
     * Creates a snapshot.
     *
     * @param directoryManager the directory manager used to decrypt names
     * @param cipherDir        the ciphertext path of the directory
     * @param entries          the entries keyed by ciphertext storage name
     * @throws NullPointerException if an argument is {@code null}
     */
    DirectorySnapshot(DirectoryManager directoryManager, String cipherDir,
                      Map<String, Entry> entries) {
        this.directoryManager = Objects.requireNonNull(directoryManager, "directoryManager");
        this.cipherDir = Objects.requireNonNull(cipherDir, "cipherDir");
        this.entries = Collections.unmodifiableMap(new HashMap<>(entries));
    }

    /**
     * Returns the changes that turned {@code previous} into this snapshot.
     *
     * <p>Only names of created, modified or deleted entries are decrypted, and
     * corrupt or undecryptable entries are skipped just as a normal directory
     * listing skips them.</p>
     *
     * @param previous the earlier snapshot
     * @return the changes, with deleted entries listed before created and
     *         modified ones
     * @throws IOException if the directory IV cannot be read while decrypting
     *                     a changed name
     * @throws NullPointerException if {@code previous} is {@code null}
     */
    public List<Change> changesSince(DirectorySnapshot previous) throws IOException {
        Objects.requireNonNull(previous, "previous");
        List<Change> changes = new ArrayList<>();
        for (Entry old : previous.entries.values()) {
            if (!entries.containsKey(old.storageName())) {
                addChange(changes, ChangeKind.DELETED, old);
            }
        }
        for (Entry now : entries.values()) {
            Entry old = previous.entries.get(now.storageName());
            if (old == null) {
                addChange(changes, ChangeKind.CREATED, now);
            } else if (!now.sameState(old)) {
                addChange(changes, ChangeKind.MODIFIED, now);
            }
        }
        return changes;
    }

    /**
     * Decrypts the name of a changed entry and adds it to {@code changes}.
     *
     * @param changes the list to add to
     * @param kind    the kind of change
     * @param entry   the changed entry
     * @throws IOException if the directory IV cannot be read
     */
    private void addChange(List<Change> changes, ChangeKind kind, Entry entry) throws IOException {
        String plainName;
        try {
            plainName = directoryManager.plainNameForCipher(cipherDir, entry.cipherName());
        } catch (IllegalArgumentException e) {
            // Corrupt or undecryptable ciphertext name: skip it.
            return;
        }
        if (!NameManager.isValidPlainName(plainName)) {
            return;
        }
        changes.add(new Change(kind, plainName));
    }

    /** The kind of change between two directory snapshots. */
    public enum ChangeKind {
        /** An entry appeared. */
        CREATED,
        /** An entry's metadata changed. */
        MODIFIED,
        /** An entry disappeared. */
        DELETED
    }

    /** A single changed directory entry with its decrypted name. */
    public static final class Change {

        /** The kind of change. */
        private final ChangeKind kind;

        /** The decrypted (plaintext) name. */
        private final String plainName;

        /**
         * Creates a change.
         *
         * @param kind      the kind of change
         * @param plainName the decrypted name
         */
        Change(ChangeKind kind, String plainName) {
            this.kind = Objects.requireNonNull(kind, "kind");
            this.plainName = Objects.requireNonNull(plainName, "plainName");
        }

        /**
         * Returns the kind of change.
         *
         * @return the kind of change
         */
        public ChangeKind kind() {
            return kind;
        }

        /**
         * Returns the decrypted (plaintext) name of the changed entry.
         *
         * @return the plaintext name
         */
        public String plainName() {
            return plainName;
        }
    }

    /** A single entry of the ciphertext listing. */
    static final class Entry {

        /** The ciphertext storage name, as returned by the store listing. */
        private final String storageName;

        /** The full ciphertext name, with long names resolved. */
        private final String cipherName;

        /** The entry kind. */
        private final CipherNode.Kind kind;

        /** The ciphertext size in bytes. */
        private final long size;

        /** The last-modified time. */
        private final FileTime lastModifiedTime;

        /**
         * Creates an entry.
         *
         * @param storageName      the ciphertext storage name
         * @param cipherName       the full ciphertext name
         * @param kind             the entry kind
         * @param size             the ciphertext size
         * @param lastModifiedTime the last-modified time
         */
        Entry(String storageName, String cipherName, CipherNode.Kind kind,
              long size, FileTime lastModifiedTime) {
            this.storageName = storageName;
            this.cipherName = cipherName;
            this.kind = kind;
            this.size = size;
            this.lastModifiedTime = lastModifiedTime;
        }

        /**
         * Returns the ciphertext storage name.
         *
         * @return the storage name
         */
        String storageName() {
            return storageName;
        }

        /**
         * Returns the full ciphertext name.
         *
         * @return the ciphertext name
         */
        String cipherName() {
            return cipherName;
        }

        /**
         * Returns whether this entry has the same state as another entry.
         *
         * @param other the other entry
         * @return {@code true} if kind, size and last-modified time are equal
         */
        boolean sameState(Entry other) {
            return kind == other.kind && size == other.size
                    && lastModifiedTime.equals(other.lastModifiedTime);
        }
    }
}
