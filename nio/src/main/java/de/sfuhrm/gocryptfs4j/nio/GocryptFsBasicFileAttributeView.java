package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

/** A basic attribute view for a gocryptfs plaintext path. */
final class GocryptFsBasicFileAttributeView implements BasicFileAttributeView {

    private final GocryptFsFileSystem fs;
    private final GocryptFsPath path;
    private final boolean followLinks;

    GocryptFsBasicFileAttributeView(GocryptFsFileSystem fs, GocryptFsPath path,
                                    boolean followLinks) {
        this.fs = fs;
        this.path = path;
        this.followLinks = followLinks;
    }

    /** The path whose attributes are accessed, following links when requested. */
    private GocryptFsPath target() throws IOException {
        return followLinks ? (GocryptFsPath) path.toRealPath() : path;
    }

    @Override
    public String name() {
        return "basic";
    }

    @Override
    public BasicFileAttributes readAttributes() throws IOException {
        return new GocryptFsFileAttributes(fs.core().stat(target().toString()));
    }

    @Override
    public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime,
                         FileTime createTime) throws IOException {
        fs.core().setTimes(target().toString(), lastModifiedTime, lastAccessTime, createTime);
    }
}
