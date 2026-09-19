package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

/**
 * A {@link BasicFileAttributeView} for a gocryptfs plaintext path.
 *
 * <p>Attribute values are read from and written to the backing cipher file.</p>
 */
final class GocryptFsBasicFileAttributeView implements BasicFileAttributeView {

    /** The filesystem the path belongs to. */
    private final GocryptFsFileSystem fs;

    /** The absolute plaintext path. */
    private final GocryptFsPath path;

    /** Whether symbolic links are followed. */
    private final boolean followLinks;

    /**
     * Creates the view.
     *
     * @param fs          the filesystem the path belongs to
     * @param path        the absolute plaintext path
     * @param followLinks whether symbolic links should be followed
     */
    GocryptFsBasicFileAttributeView(GocryptFsFileSystem fs, GocryptFsPath path,
                                    boolean followLinks) {
        this.fs = fs;
        this.path = path;
        this.followLinks = followLinks;
    }

    /**
     * Returns the path whose attributes are accessed, following links if
     * requested.
     *
     * @return the resolved path
     * @throws IOException on filesystem errors while resolving links
     */
    private GocryptFsPath target() throws IOException {
        return followLinks ? (GocryptFsPath) path.toRealPath() : path;
    }

    /**
     * Returns the view name.
     *
     * @return the string {@code "basic"}
     */
    @Override
    public String name() {
        return "basic";
    }

    /**
     * Reads the basic attributes of the target.
     *
     * @return the attributes
     * @throws IOException on filesystem errors
     */
    @Override
    public BasicFileAttributes readAttributes() throws IOException {
        return new GocryptFsFileAttributes(fs.core().stat(target().toString()));
    }

    /**
     * Sets the times of the target.
     *
     * @param lastModifiedTime the new last-modified time, or {@code null} to leave unchanged
     * @param lastAccessTime   the new last-access time, or {@code null} to leave unchanged
     * @param createTime       the new creation time, or {@code null} to leave unchanged
     * @throws IOException on filesystem errors
     */
    @Override
    public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime,
                         FileTime createTime) throws IOException {
        fs.core().setTimes(target().toString(), lastModifiedTime, lastAccessTime, createTime);
    }
}
