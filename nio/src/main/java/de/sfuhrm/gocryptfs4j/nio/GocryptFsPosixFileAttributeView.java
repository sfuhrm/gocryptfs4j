package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

/**
 * A {@link PosixFileAttributeView} for a gocryptfs plaintext path.
 *
 * <p>Ownership and permission changes are applied to the backing cipher file,
 * since gocryptfs does not store them separately.</p>
 */
final class GocryptFsPosixFileAttributeView implements PosixFileAttributeView {

    private final GocryptFsFileSystem fs;
    private final GocryptFsPath path;
    private final boolean followLinks;

    GocryptFsPosixFileAttributeView(GocryptFsFileSystem fs, GocryptFsPath path,
                                    boolean followLinks) {
        this.fs = fs;
        this.path = path;
        this.followLinks = followLinks;
    }

    @Override
    public String name() {
        return "posix";
    }

    /** The path whose attributes are accessed, following links when requested. */
    private GocryptFsPath target() throws IOException {
        return followLinks ? (GocryptFsPath) path.toRealPath() : path;
    }

    /** The backing cipher path of the target. */
    private Path cipherPath() throws IOException {
        return fs.core().resolve(target().toString()).cipherPath;
    }

    /** The POSIX view of the backing cipher file. */
    private PosixFileAttributeView delegate() throws IOException {
        return GocryptFsProvider.posixView(cipherPath());
    }

    @Override
    public PosixFileAttributes readAttributes() throws IOException {
        return GocryptFsProvider.readPosixAttributes(target());
    }

    @Override
    public void setPermissions(Set<PosixFilePermission> perms) throws IOException {
        delegate().setPermissions(perms);
    }

    @Override
    public void setGroup(GroupPrincipal group) throws IOException {
        delegate().setGroup(group);
    }

    @Override
    public UserPrincipal getOwner() throws IOException {
        return delegate().getOwner();
    }

    @Override
    public void setOwner(UserPrincipal owner) throws IOException {
        delegate().setOwner(owner);
    }

    @Override
    public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime)
            throws IOException {
        delegate().setTimes(lastModifiedTime, lastAccessTime, createTime);
    }
}
