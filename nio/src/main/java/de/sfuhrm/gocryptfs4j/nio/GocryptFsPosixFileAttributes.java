package de.sfuhrm.gocryptfs4j.nio;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * {@link PosixFileAttributes} for a gocryptfs plaintext path.
 *
 * <p>The basic attributes are taken from the supplied {@link BasicFileAttributes}
 * (so the reported size is the plaintext size), while owner, group and
 * permissions are the POSIX metadata of the backing cipher file. gocryptfs does
 * not persist ownership or permissions itself, so the backing file's metadata is
 * the only available source.</p>
 */
final class GocryptFsPosixFileAttributes implements PosixFileAttributes {

    /** The basic attributes (and plaintext size) of the path. */
    private final BasicFileAttributes basic;

    /** The owner of the backing file, or {@code null} if unknown. */
    private final UserPrincipal owner;

    /** The group of the backing file, or {@code null} if unknown. */
    private final GroupPrincipal group;

    /** The permissions of the backing file; never {@code null}. */
    private final Set<PosixFilePermission> permissions;

    /**
     * Creates the attributes.
     *
     * @param basic       the basic attributes (and plaintext size)
     * @param owner       the owner, or {@code null}
     * @param group       the group, or {@code null}
     * @param permissions the permissions, or {@code null} for none
     * @throws NullPointerException if {@code basic} is {@code null}
     */
    GocryptFsPosixFileAttributes(BasicFileAttributes basic, UserPrincipal owner,
                                 GroupPrincipal group, Set<PosixFilePermission> permissions) {
        this.basic = Objects.requireNonNull(basic, "basic");
        this.owner = owner;
        this.group = group;
        this.permissions = permissions == null
                ? Collections.<PosixFilePermission>emptySet()
                : Collections.unmodifiableSet(new LinkedHashSet<>(permissions));
    }

    /**
     * Returns the last-modified time.
     *
     * @return the last-modified time
     */
    @Override
    public FileTime lastModifiedTime() {
        return basic.lastModifiedTime();
    }

    /**
     * Returns the last-access time.
     *
     * @return the last-access time
     */
    @Override
    public FileTime lastAccessTime() {
        return basic.lastAccessTime();
    }

    /**
     * Returns the creation time.
     *
     * @return the creation time
     */
    @Override
    public FileTime creationTime() {
        return basic.creationTime();
    }

    /**
     * Returns whether the path is a regular file.
     *
     * @return {@code true} if the path is a regular file
     */
    @Override
    public boolean isRegularFile() {
        return basic.isRegularFile();
    }

    /**
     * Returns whether the path is a directory.
     *
     * @return {@code true} if the path is a directory
     */
    @Override
    public boolean isDirectory() {
        return basic.isDirectory();
    }

    /**
     * Returns whether the path is a symbolic link.
     *
     * @return {@code true} if the path is a symbolic link
     */
    @Override
    public boolean isSymbolicLink() {
        return basic.isSymbolicLink();
    }

    /**
     * Returns whether the path is of some other kind.
     *
     * @return {@code true} if the path is neither a regular file, directory nor symbolic link
     */
    @Override
    public boolean isOther() {
        return basic.isOther();
    }

    /**
     * Returns the plaintext size.
     *
     * @return the plaintext size in bytes
     */
    @Override
    public long size() {
        return basic.size();
    }

    /**
     * Returns the file key, or {@code null} if there is none.
     *
     * @return the file key, or {@code null}
     */
    @Override
    public Object fileKey() {
        return basic.fileKey();
    }

    /**
     * Returns the owner of the backing file.
     *
     * @return the owner, or {@code null} if unknown
     */
    @Override
    public UserPrincipal owner() {
        return owner;
    }

    /**
     * Returns the group of the backing file.
     *
     * @return the group, or {@code null} if unknown
     */
    @Override
    public GroupPrincipal group() {
        return group;
    }

    /**
     * Returns the permissions of the backing file.
     *
     * @return an unmodifiable set of permissions
     */
    @Override
    public Set<PosixFilePermission> permissions() {
        return permissions;
    }
}
