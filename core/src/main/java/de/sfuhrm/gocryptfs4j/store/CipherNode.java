package de.sfuhrm.gocryptfs4j.store;

import org.jspecify.annotations.Nullable;

import java.nio.file.attribute.FileTime;

/**
 * A single ciphertext-side directory entry returned by
 * {@link CipherStore#list(String)} and {@link CipherStore#stat(String)}.
 *
 * <p>A node carries the on-disk (ciphertext) name and the basic attributes of
 * the entry. The plaintext name and plaintext size are derived from these by
 * {@code GocryptFs}, not by the store.</p>
 */
public interface CipherNode {

    /** Kind of a ciphertext entry, mirroring the plaintext view's kind. */
    enum Kind {
        /** A regular file. */
        FILE,
        /** A directory. */
        DIRECTORY,
        /** A symbolic link. */
        SYMLINK,
        /** Any other kind of entry. */
        OTHER
    }

    /**
     * Returns the ciphertext (on-disk) name of this entry.
     *
     * @return the ciphertext name
     */
    String name();

    /**
     * Returns the kind of this entry.
     *
     * @return the entry kind
     */
    Kind kind();

    /**
     * Returns the ciphertext size in bytes.
     *
     * @return the ciphertext size
     */
    long size();

    /**
     * Returns the last-modified time.
     *
     * @return the last-modified time
     */
    FileTime lastModifiedTime();

    /**
     * Returns the last-access time.
     *
     * @return the last-access time
     */
    FileTime lastAccessTime();

    /**
     * Returns the creation time.
     *
     * @return the creation time
     */
    FileTime creationTime();

    /**
     * Returns the file key, or {@code null} if the store has none.
     *
     * @return the file key, or {@code null}
     */
    @Nullable Object fileKey();

    /**
     * Returns whether this entry is a directory.
     *
     * @return {@code true} if this entry is a directory
     */
    default boolean isDirectory() {
        return kind() == Kind.DIRECTORY;
    }

    /**
     * Returns whether this entry is a regular file.
     *
     * @return {@code true} if this entry is a regular file
     */
    default boolean isRegularFile() {
        return kind() == Kind.FILE;
    }

    /**
     * Returns whether this entry is a symbolic link.
     *
     * @return {@code true} if this entry is a symbolic link
     */
    default boolean isSymbolicLink() {
        return kind() == Kind.SYMLINK;
    }
}
