package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.DirEntry;
import org.jspecify.annotations.Nullable;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

/**
 * {@link BasicFileAttributes} for a gocryptfs plaintext path.
 *
 * <p>All values are taken from the underlying {@link DirEntry}, so the reported
 * size is the plaintext size.</p>
 */
final class GocryptFsFileAttributes implements BasicFileAttributes {

    /** The directory entry whose attributes are exposed. */
    private final DirEntry entry;

    /**
     * Creates the attributes.
     *
     * @param entry the directory entry whose attributes are exposed
     */
    GocryptFsFileAttributes(DirEntry entry) {
        this.entry = entry;
    }

    /**
     * Returns the last-modified time.
     *
     * @return the last-modified time
     */
    @Override
    public FileTime lastModifiedTime() {
        return entry.lastModifiedTime();
    }

    /**
     * Returns the last-access time.
     *
     * @return the last-access time
     */
    @Override
    public FileTime lastAccessTime() {
        return entry.lastAccessTime();
    }

    /**
     * Returns the creation time.
     *
     * @return the creation time
     */
    @Override
    public FileTime creationTime() {
        return entry.creationTime();
    }

    /**
     * Returns whether the entry is a regular file.
     *
     * @return {@code true} if the entry is a regular file
     */
    @Override
    public boolean isRegularFile() {
        return entry.isRegularFile();
    }

    /**
     * Returns whether the entry is a directory.
     *
     * @return {@code true} if the entry is a directory
     */
    @Override
    public boolean isDirectory() {
        return entry.isDirectory();
    }

    /**
     * Returns whether the entry is a symbolic link.
     *
     * @return {@code true} if the entry is a symbolic link
     */
    @Override
    public boolean isSymbolicLink() {
        return entry.isSymbolicLink();
    }

    /**
     * Returns whether the entry is of some other kind.
     *
     * @return {@code true} if the entry is neither a regular file, directory nor symbolic link
     */
    @Override
    public boolean isOther() {
        return entry.kind() == DirEntry.Kind.OTHER;
    }

    /**
     * Returns the plaintext size.
     *
     * @return the plaintext size in bytes
     */
    @Override
    public long size() {
        return entry.size();
    }

    /**
     * Returns the file key, or {@code null} if there is none.
     *
     * @return the file key, or {@code null}
     */
    @Override
    public @Nullable Object fileKey() {
        return entry.fileKey();
    }
}
