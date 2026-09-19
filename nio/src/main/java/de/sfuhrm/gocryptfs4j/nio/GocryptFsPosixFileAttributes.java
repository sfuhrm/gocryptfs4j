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

    private final BasicFileAttributes basic;
    private final UserPrincipal owner;
    private final GroupPrincipal group;
    private final Set<PosixFilePermission> permissions;

    GocryptFsPosixFileAttributes(BasicFileAttributes basic, UserPrincipal owner,
                                 GroupPrincipal group, Set<PosixFilePermission> permissions) {
        this.basic = Objects.requireNonNull(basic, "basic");
        this.owner = owner;
        this.group = group;
        this.permissions = permissions == null
                ? Collections.<PosixFilePermission>emptySet()
                : Collections.unmodifiableSet(new LinkedHashSet<>(permissions));
    }

    @Override
    public FileTime lastModifiedTime() {
        return basic.lastModifiedTime();
    }

    @Override
    public FileTime lastAccessTime() {
        return basic.lastAccessTime();
    }

    @Override
    public FileTime creationTime() {
        return basic.creationTime();
    }

    @Override
    public boolean isRegularFile() {
        return basic.isRegularFile();
    }

    @Override
    public boolean isDirectory() {
        return basic.isDirectory();
    }

    @Override
    public boolean isSymbolicLink() {
        return basic.isSymbolicLink();
    }

    @Override
    public boolean isOther() {
        return basic.isOther();
    }

    @Override
    public long size() {
        return basic.size();
    }

    @Override
    public Object fileKey() {
        return basic.fileKey();
    }

    @Override
    public UserPrincipal owner() {
        return owner;
    }

    @Override
    public GroupPrincipal group() {
        return group;
    }

    @Override
    public Set<PosixFilePermission> permissions() {
        return permissions;
    }
}
