package de.sfuhrm.gocryptfs4j.nio;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileStoreAttributeView;

/**
 * A {@link FileStore} representing the gocryptfs cipher directory.
 *
 * <p>Space information and the read-only flag are delegated to the backing file
 * store of the cipher directory. Attribute views are limited to the basic view
 * and, when the backing filesystem supports it, the POSIX and owner views.</p>
 */
final class GocryptFsFileStore extends FileStore {

    /** The filesystem this store belongs to. */
    private final GocryptFsFileSystem fs;

    /**
     * Creates the store.
     *
     * @param fs the filesystem this store belongs to
     */
    GocryptFsFileStore(GocryptFsFileSystem fs) {
        this.fs = fs;
    }

    /**
     * Returns the store name.
     *
     * @return the string {@code "gocryptfs"}
     */
    @Override
    public String name() {
        return "gocryptfs";
    }

    /**
     * Returns the store type.
     *
     * @return the string {@code "gocryptfs"}
     */
    @Override
    public String type() {
        return "gocryptfs";
    }

    /**
     * Returns whether the backing store is read-only.
     *
     * @return {@code true} if the backing store is read-only
     */
    @Override
    public boolean isReadOnly() {
        return fs.isReadOnly();
    }

    /**
     * Returns the total space of the backing store.
     *
     * @return the total space in bytes
     * @throws IOException on filesystem errors
     */
    @Override
    public long getTotalSpace() throws IOException {
        return java.nio.file.Files.getFileStore(fs.core().cipherRoot()).getTotalSpace();
    }

    /**
     * Returns the usable space of the backing store.
     *
     * @return the usable space in bytes
     * @throws IOException on filesystem errors
     */
    @Override
    public long getUsableSpace() throws IOException {
        return java.nio.file.Files.getFileStore(fs.core().cipherRoot()).getUsableSpace();
    }

    /**
     * Returns the unallocated space of the backing store.
     *
     * @return the unallocated space in bytes
     * @throws IOException on filesystem errors
     */
    @Override
    public long getUnallocatedSpace() throws IOException {
        return java.nio.file.Files.getFileStore(fs.core().cipherRoot()).getUnallocatedSpace();
    }

    /**
     * Returns whether the given attribute view type is supported.
     *
     * @param type the attribute view type
     * @return {@code true} if the view is supported
     */
    @Override
    public boolean supportsFileAttributeView(Class<? extends FileAttributeView> type) {
        if (type == java.nio.file.attribute.BasicFileAttributeView.class) {
            return true;
        }
        if (type == java.nio.file.attribute.PosixFileAttributeView.class
                || type == java.nio.file.attribute.FileOwnerAttributeView.class) {
            return fs.supportsPosix();
        }
        return false;
    }

    /**
     * Returns whether the named attribute view is supported.
     *
     * @param name the attribute view name
     * @return {@code true} if the view is supported
     */
    @Override
    public boolean supportsFileAttributeView(String name) {
        if ("basic".equals(name)) {
            return true;
        }
        if ("posix".equals(name) || "owner".equals(name)) {
            return fs.supportsPosix();
        }
        return false;
    }

    /**
     * Returns a file store attribute view, if any. This implementation supports
     * none, so it always returns {@code null}.
     *
     * @param <V>  the view type
     * @param type the view type
     * @return always {@code null}
     */
    @Override
    public <V extends FileStoreAttributeView> @Nullable V getFileStoreAttributeView(Class<V> type) {
        return null;
    }

    /**
     * Returns the value of the named store attribute.
     *
     * @param attribute the attribute name
     * @return the attribute value, or {@code null} if the attribute is unknown
     * @throws IOException on filesystem errors
     */
    @Override
    public @Nullable Object getAttribute(String attribute) throws IOException {
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
