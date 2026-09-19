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

    /** The filesystem this service belongs to. */
    private final GocryptFsFileSystem fs;

    /**
     * Creates the service.
     *
     * @param fs the filesystem this service belongs to
     */
    GocryptFsUserPrincipalLookupService(GocryptFsFileSystem fs) {
        this.fs = fs;
    }

    /**
     * Looks up a user principal by name. This implementation always creates a
     * principal for the given name.
     *
     * @param name the user name
     * @return the principal
     * @throws NullPointerException if {@code name} is {@code null}
     * @throws IOException never thrown by this implementation
     */
    @Override
    public UserPrincipal lookupPrincipalByName(String name) throws IOException {
        return new GocryptFsUserPrincipal(Objects.requireNonNull(name, "name"));
    }

    /**
     * Looks up a group principal by name. This implementation always creates a
     * principal for the given name.
     *
     * @param group the group name
     * @return the principal
     * @throws NullPointerException if {@code group} is {@code null}
     * @throws IOException never thrown by this implementation
     */
    @Override
    public GroupPrincipal lookupPrincipalByGroupName(String group) throws IOException {
        return new GocryptFsGroupPrincipal(Objects.requireNonNull(group, "group"));
    }
}

/**
 * A {@link UserPrincipal} identified only by name.
 */
class GocryptFsUserPrincipal implements UserPrincipal {

    /** The principal name. */
    private final String name;

    /**
     * Creates a principal.
     *
     * @param name the principal name
     */
    GocryptFsUserPrincipal(String name) {
        this.name = name;
    }

    /**
     * Returns the principal name.
     *
     * @return the principal name
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * Compares this principal to another object. Two principals are equal if
     * they are of the same type and have the same name.
     *
     * @param o the object to compare to
     * @return {@code true} if the objects are equal
     */
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

    /**
     * Returns a hash code consistent with {@link #equals(Object)}.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return name.hashCode();
    }

    /**
     * Returns the principal name.
     *
     * @return the principal name
     */
    @Override
    public String toString() {
        return name;
    }
}

/**
 * A {@link GroupPrincipal} identified only by name.
 */
final class GocryptFsGroupPrincipal extends GocryptFsUserPrincipal implements GroupPrincipal {

    /**
     * Creates a group principal.
     *
     * @param name the group name
     */
    GocryptFsGroupPrincipal(String name) {
        super(name);
    }
}
