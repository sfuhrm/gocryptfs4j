package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

/** A basic attribute view for a gocryptfs plaintext path. */
final class GocryptFsBasicFileAttributeView implements BasicFileAttributeView {

    private final GocryptFsFileSystem fs;
    private final GocryptFsPath path;

    GocryptFsBasicFileAttributeView(GocryptFsFileSystem fs, GocryptFsPath path) {
        this.fs = fs;
        this.path = path;
    }

    @Override
    public String name() {
        return "basic";
    }

    @Override
    public BasicFileAttributes readAttributes() throws IOException {
        return new GocryptFsFileAttributes(fs.core().stat(path.toString()));
    }

    @Override
    public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime,
                         FileTime createTime) throws IOException {
        fs.core().setTimes(path.toString(), lastModifiedTime, lastAccessTime, createTime);
    }
}
