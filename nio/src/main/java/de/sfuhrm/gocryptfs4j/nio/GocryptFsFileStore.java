package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileStoreAttributeView;

/** A simple {@link FileStore} over the gocryptfs cipher directory. */
final class GocryptFsFileStore extends FileStore {

    private final GocryptFsFileSystem fs;

    GocryptFsFileStore(GocryptFsFileSystem fs) {
        this.fs = fs;
    }

    @Override
    public String name() {
        return "gocryptfs";
    }

    @Override
    public String type() {
        return "gocryptfs";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public long getTotalSpace() throws IOException {
        return java.nio.file.Files.getFileStore(fs.core().cipherRoot()).getTotalSpace();
    }

    @Override
    public long getUsableSpace() throws IOException {
        return java.nio.file.Files.getFileStore(fs.core().cipherRoot()).getUsableSpace();
    }

    @Override
    public long getUnallocatedSpace() throws IOException {
        return java.nio.file.Files.getFileStore(fs.core().cipherRoot()).getUnallocatedSpace();
    }

    @Override
    public boolean supportsFileAttributeView(Class<? extends FileAttributeView> type) {
        return type == java.nio.file.attribute.BasicFileAttributeView.class;
    }

    @Override
    public boolean supportsFileAttributeView(String name) {
        return "basic".equals(name);
    }

    @Override
    public <V extends FileStoreAttributeView> V getFileStoreAttributeView(Class<V> type) {
        return null;
    }

    @Override
    public Object getAttribute(String attribute) throws IOException {
        if ("totalSpace".equals(attribute)) {
            return getTotalSpace();
        }
        if ("usableSpace".equals(attribute)) {
            return getUsableSpace();
        }
        if ("unallocatedSpace".equals(attribute)) {
            return getUnallocatedSpace();
        }
        return null;
    }
}
