package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.fs.DirEntry;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

/** {@link BasicFileAttributes} for a gocryptfs plaintext path. */
final class GocryptFsFileAttributes implements BasicFileAttributes {

    private final DirEntry entry;

    GocryptFsFileAttributes(DirEntry entry) {
        this.entry = entry;
    }

    @Override
    public FileTime lastModifiedTime() {
        return entry.lastModifiedTime();
    }

    @Override
    public FileTime lastAccessTime() {
        return entry.lastAccessTime();
    }

    @Override
    public FileTime creationTime() {
        return entry.creationTime();
    }

    @Override
    public boolean isRegularFile() {
        return entry.isRegularFile();
    }

    @Override
    public boolean isDirectory() {
        return entry.isDirectory();
    }

    @Override
    public boolean isSymbolicLink() {
        return entry.isSymbolicLink();
    }

    @Override
    public boolean isOther() {
        return entry.kind() == DirEntry.Kind.OTHER;
    }

    @Override
    public long size() {
        return entry.size();
    }

    @Override
    public Object fileKey() {
        return entry.fileKey();
    }
}
