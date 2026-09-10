package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Objects;

/**
 * A {@link UserPrincipalLookupService} for gocryptfs.
 *
 * <p>gocryptfs does not persist ownership information, so principals are
 * created on demand from the requested name and are never rejected.</p>
 */
final class GocryptFsUserPrincipalLookupService extends UserPrincipalLookupService {

    private final GocryptFsFileSystem fs;

    GocryptFsUserPrincipalLookupService(GocryptFsFileSystem fs) {
        this.fs = fs;
    }

    @Override
    public UserPrincipal lookupPrincipalByName(String name) throws IOException {
        return new GocryptFsUserPrincipal(Objects.requireNonNull(name, "name"));
    }

    @Override
    public GroupPrincipal lookupPrincipalByGroupName(String group) throws IOException {
        return new GocryptFsGroupPrincipal(Objects.requireNonNull(group, "group"));
    }
}

/** A {@link UserPrincipal} identified only by name. */
class GocryptFsUserPrincipal implements UserPrincipal {

    private final String name;

    GocryptFsUserPrincipal(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof GocryptFsUserPrincipal)) {
            return false;
        }
        return name.equals(((GocryptFsUserPrincipal) o).name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public String toString() {
        return name;
    }
}

/** A {@link GroupPrincipal} identified only by name. */
final class GocryptFsGroupPrincipal extends GocryptFsUserPrincipal implements GroupPrincipal {

    GocryptFsGroupPrincipal(String name) {
        super(name);
    }
}
