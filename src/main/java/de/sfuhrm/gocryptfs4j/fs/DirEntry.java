package de.sfuhrm.gocryptfs4j.fs;

import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

/**
 * A directory entry of the decrypted (plaintext) view.
 */
public final class DirEntry {

    /** Kind of a directory entry. */
    public enum Kind {
        /** A regular file. */
        FILE,
        /** A directory. */
        DIRECTORY,
        /** A symbolic link. */
        SYMLINK,
        /** Any other kind of entry. */
        OTHER
    }

    private final String plainName;
    private final String cipherName;
    private final Path cipherPath;
    private final Kind kind;
    private final long size;
    private final FileTime lastModifiedTime;
    private final FileTime lastAccessTime;
    private final FileTime creationTime;
    private final Object fileKey;

    /**
     * Creates a directory entry.
     *
     * @param plainName        the plaintext (decrypted) name
     * @param cipherName       the ciphertext (encrypted) name
     * @param cipherPath       the ciphertext-side path
     * @param kind             the entry kind
     * @param size             the plaintext size in bytes
     * @param lastModifiedTime the last-modified time
     * @param lastAccessTime   the last-access time
     * @param creationTime     the creation time
     * @param fileKey          the file key
     */
    public DirEntry(String plainName, String cipherName, Path cipherPath, Kind kind, long size,
                    FileTime lastModifiedTime, FileTime lastAccessTime, FileTime creationTime,
                    Object fileKey) {
        this.plainName = plainName;
        this.cipherName = cipherName;
        this.cipherPath = cipherPath;
        this.kind = kind;
        this.size = size;
        this.lastModifiedTime = lastModifiedTime;
        this.lastAccessTime = lastAccessTime;
        this.creationTime = creationTime;
        this.fileKey = fileKey;
    }

    /**
     * Returns the plaintext (decrypted) name.
     *
     * @return the plaintext (decrypted) name
     */
    public String plainName() {
        return plainName;
    }

    /**
     * Returns the ciphertext (encrypted) name.
     *
     * @return the ciphertext (encrypted) name
     */
    public String cipherName() {
        return cipherName;
    }

    /**
     * Returns the ciphertext-side path.
     *
     * @return the ciphertext-side path
     */
    public Path cipherPath() {
        return cipherPath;
    }

    /**
     * Returns the entry kind.
     *
     * @return the entry kind
     */
    public Kind kind() {
        return kind;
    }

    /**
     * Returns whether this entry is a directory.
     *
     * @return true if this entry is a directory
     */
    public boolean isDirectory() {
        return kind == Kind.DIRECTORY;
    }

    /**
     * Returns whether this entry is a regular file.
     *
     * @return true if this entry is a regular file
     */
    public boolean isRegularFile() {
        return kind == Kind.FILE;
    }

    /**
     * Returns whether this entry is a symbolic link.
     *
     * @return true if this entry is a symbolic link
     */
    public boolean isSymbolicLink() {
        return kind == Kind.SYMLINK;
    }

    /**
     * Returns the plaintext size in bytes.
     *
     * @return the plaintext size in bytes
     */
    public long size() {
        return size;
    }

    /**
     * Returns the last-modified time.
     *
     * @return the last-modified time
     */
    public FileTime lastModifiedTime() {
        return lastModifiedTime;
    }

    /**
     * Returns the last-access time.
     *
     * @return the last-access time
     */
    public FileTime lastAccessTime() {
        return lastAccessTime;
    }

    /**
     * Returns the creation time.
     *
     * @return the creation time
     */
    public FileTime creationTime() {
        return creationTime;
    }

    /**
     * Returns the file key.
     *
     * @return the file key
     */
    public Object fileKey() {
        return fileKey;
    }
}
