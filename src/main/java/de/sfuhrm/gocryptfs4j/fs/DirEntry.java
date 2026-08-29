package de.sfuhrm.gocryptfs4j.fs;

import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

/**
 * A directory entry of the decrypted (plaintext) view.
 */
public final class DirEntry {

    /** Kind of a directory entry. */
    public enum Kind {
        FILE, DIRECTORY, SYMLINK, OTHER
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

    public String plainName() {
        return plainName;
    }

    public String cipherName() {
        return cipherName;
    }

    public Path cipherPath() {
        return cipherPath;
    }

    public Kind kind() {
        return kind;
    }

    public boolean isDirectory() {
        return kind == Kind.DIRECTORY;
    }

    public boolean isRegularFile() {
        return kind == Kind.FILE;
    }

    public boolean isSymbolicLink() {
        return kind == Kind.SYMLINK;
    }

    public long size() {
        return size;
    }

    public FileTime lastModifiedTime() {
        return lastModifiedTime;
    }

    public FileTime lastAccessTime() {
        return lastAccessTime;
    }

    public FileTime creationTime() {
        return creationTime;
    }

    public Object fileKey() {
        return fileKey;
    }
}
