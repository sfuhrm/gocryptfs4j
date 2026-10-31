package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * A {@link PosixFileAttributeView} for a gocryptfs plaintext path.
 *
 * <p>Ownership and permission changes are applied to the backing cipher file,
 * since gocryptfs does not store them separately.</p>
 */
final class GocryptFsPosixFileAttributeView implements PosixFileAttributeView {

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
    GocryptFsPosixFileAttributeView(GocryptFsFileSystem fs, GocryptFsPath path,
                                    boolean followLinks) {
        this.fs = fs;
        this.path = path;
        this.followLinks = followLinks;
    }

    /**
     * Returns the view name.
     *
     * @return the string {@code "posix"}
     */
    @Override
    public String name() {
        return "posix";
    }

    /**
     * Returns the path whose attributes are accessed, following links if
     * requested.
     *
     * @return the resolved path
     * @throws IOException on filesystem errors while resolving links
     */
    private GocryptFsPath target() throws IOException {
        return followLinks ? path.toRealPathLenient() : path;
    }

    /**
     * Reads the POSIX attributes of the target.
     *
     * @return the attributes
     * @throws IOException on filesystem errors
     */
    @Override
    public PosixFileAttributes readAttributes() throws IOException {
        return GocryptFsProvider.readPosixAttributes(target());
    }

    /**
     * Sets the permissions of the backing cipher file.
     *
     * @param perms the new permissions
     * @throws IOException on filesystem errors
     */
    @Override
    public void setPermissions(Set<PosixFilePermission> perms) throws IOException {
        fs.core().setPosixPermissions(target().toString(), perms);
    }

    /**
     * Sets the group of the backing cipher file.
     *
     * @param group the new group
     * @throws IOException on filesystem errors
     */
    @Override
    public void setGroup(GroupPrincipal group) throws IOException {
        fs.core().setPosixGroup(target().toString(), group);
    }

    /**
     * Returns the owner of the backing cipher file.
     *
     * @return the owner
     * @throws IOException on filesystem errors
     */
    @Override
    public UserPrincipal getOwner() throws IOException {
        return readAttributes().owner();
    }

    /**
     * Sets the owner of the backing cipher file.
     *
     * @param owner the new owner
     * @throws IOException on filesystem errors
     */
    @Override
    public void setOwner(UserPrincipal owner) throws IOException {
        fs.core().setPosixOwner(target().toString(), owner);
    }

    /**
     * Sets the times of the backing cipher file.
     *
     * @param lastModifiedTime the new last-modified time, or {@code null} to leave unchanged
     * @param lastAccessTime   the new last-access time, or {@code null} to leave unchanged
     * @param createTime       the new creation time, or {@code null} to leave unchanged
     * @throws IOException on filesystem errors
     */
    @Override
    public void setTimes(@Nullable FileTime lastModifiedTime, @Nullable FileTime lastAccessTime,
                         @Nullable FileTime createTime) throws IOException {
        fs.core().setTimes(target().toString(), lastModifiedTime, lastAccessTime, createTime);
    }
}
