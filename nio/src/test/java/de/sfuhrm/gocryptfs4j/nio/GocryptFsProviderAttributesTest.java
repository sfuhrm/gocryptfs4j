package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.DirEntry;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@code [view:]attribute-list} parsing of the attribute
 * helpers in {@link GocryptFsProvider}.
 *
 * <p>These use a synthetic {@link DirEntry} so the edge cases (notably a
 * {@code null} file key and the exception types) can be exercised without a
 * backing filesystem.</p>
 */
class GocryptFsProviderAttributesTest {

    private static final Path CIPHER_PATH = Paths.get("/cipher/cipher-name");

    private static DirEntry entry(Object fileKey) {
        return new DirEntry("file.txt", "cipher-name", CIPHER_PATH, DirEntry.Kind.FILE, 42L,
                FileTime.fromMillis(3000), FileTime.fromMillis(2000),
                FileTime.fromMillis(1000), fileKey);
    }

    private static GocryptFsPosixFileAttributes posixEntry() {
        UserPrincipal owner = () -> "user";
        GroupPrincipal group = () -> "group";
        Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-r--r--");
        return new GocryptFsPosixFileAttributes(new GocryptFsFileAttributes(entry(null)),
                owner, group, permissions);
    }

    @Test
    void wildcardReturnsAllBasicAttributes() {
        for (String spec : Arrays.asList("*", "basic:*")) {
            Map<String, Object> attrs = GocryptFsProvider.basicAttributes(entry(null), spec);
            Set<String> expected = new HashSet<>(Arrays.asList(
                    "size", "creationTime", "lastModifiedTime", "lastAccessTime",
                    "isRegularFile", "isDirectory", "isSymbolicLink", "isOther", "fileKey"));
            assertEquals(expected, attrs.keySet(), spec);
            assertEquals(42L, attrs.get("size"), spec);
            assertEquals(FileTime.fromMillis(3000), attrs.get("lastModifiedTime"), spec);
            assertEquals(Boolean.TRUE, attrs.get("isRegularFile"), spec);
            assertEquals(Boolean.FALSE, attrs.get("isDirectory"), spec);
        }
    }

    @Test
    void viewQualifiedAttributesUseBareKeys() {
        Map<String, Object> attrs = GocryptFsProvider.basicAttributes(entry(null), "basic:size");
        assertEquals(1, attrs.size());
        assertEquals(42L, attrs.get("size"));
        assertFalse(attrs.containsKey("basic:size"));
    }

    @Test
    void attributeListIsParsedStrictly() {
        Map<String, Object> attrs = GocryptFsProvider.basicAttributes(entry(null),
                "size,isRegularFile,isDirectory");
        assertEquals(42L, attrs.get("size"));
        assertEquals(Boolean.TRUE, attrs.get("isRegularFile"));
        assertEquals(Boolean.FALSE, attrs.get("isDirectory"));

        assertThrows(IllegalArgumentException.class,
                () -> GocryptFsProvider.basicAttributes(entry(null), "size, isRegularFile"));
    }

    @Test
    void wildcardCombinesWithExplicitNames() {
        Map<String, Object> attrs = GocryptFsProvider.basicAttributes(entry(null), "*,size");
        assertEquals(42L, attrs.get("size"));
        assertTrue(attrs.containsKey("isOther"));
    }

    @Test
    void nullFileKeyIsReturnedAsNull() {
        Map<String, Object> attrs = GocryptFsProvider.basicAttributes(entry(null), "fileKey");
        assertTrue(attrs.containsKey("fileKey"));
        assertNull(attrs.get("fileKey"));

        Map<String, Object> all = GocryptFsProvider.basicAttributes(entry(null), "*");
        assertTrue(all.containsKey("fileKey"));
        assertNull(all.get("fileKey"));
    }

    @Test
    void nonNullFileKeyIsReturned() {
        Object key = new Object();
        Map<String, Object> attrs = GocryptFsProvider.basicAttributes(entry(key), "fileKey");
        assertSame(key, attrs.get("fileKey"));
    }

    @Test
    void unsupportedViewIsRejected() {
        assertThrows(UnsupportedOperationException.class,
                () -> GocryptFsProvider.basicAttributes(entry(null), "posix:size"));
        assertThrows(UnsupportedOperationException.class,
                () -> GocryptFsProvider.basicAttributes(entry(null), "bogus:*"));
    }

    @Test
    void unknownAttributeIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> GocryptFsProvider.basicAttributes(entry(null), "bogus"));
        assertThrows(IllegalArgumentException.class,
                () -> GocryptFsProvider.basicAttributes(entry(null), "size,bogus"));
    }

    @Test
    void emptyAttributeSpecificationIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> GocryptFsProvider.basicAttributes(entry(null), ""));
        assertThrows(IllegalArgumentException.class,
                () -> GocryptFsProvider.basicAttributes(entry(null), "basic:"));
    }

    @Test
    void posixWildcardReturnsBasicPlusPosixAttributes() {
        Map<String, Object> attrs = GocryptFsProvider.posixAttributes(posixEntry(), "posix:*");
        assertTrue(attrs.containsKey("owner"));
        assertTrue(attrs.containsKey("group"));
        assertTrue(attrs.containsKey("permissions"));
        assertTrue(attrs.containsKey("size"));
        assertTrue(attrs.containsKey("fileKey"));
        assertEquals(42L, attrs.get("size"));
        assertEquals(PosixFilePermissions.fromString("rw-r--r--"), attrs.get("permissions"));
    }

    @Test
    void posixNamedAttributes() {
        Map<String, Object> mixed = GocryptFsProvider.posixAttributes(posixEntry(),
                "posix:owner,group,size");
        assertEquals("user", ((UserPrincipal) mixed.get("owner")).getName());
        assertEquals("group", ((GroupPrincipal) mixed.get("group")).getName());
        assertEquals(42L, mixed.get("size"));

        assertThrows(IllegalArgumentException.class,
                () -> GocryptFsProvider.posixAttributes(posixEntry(), "posix:bogus"));
        assertThrows(UnsupportedOperationException.class,
                () -> GocryptFsProvider.posixAttributes(posixEntry(), "basic:size"));
        assertThrows(UnsupportedOperationException.class,
                () -> GocryptFsProvider.posixAttributes(posixEntry(), "owner:owner"));
    }

    @Test
    void ownerViewOnlyAcceptsOwner() {
        UserPrincipal owner = () -> "user";
        Map<String, Object> wildcard = GocryptFsProvider.ownerAttributes(owner, "owner:*");
        assertSame(owner, wildcard.get("owner"));
        Map<String, Object> named = GocryptFsProvider.ownerAttributes(owner, "owner:owner");
        assertSame(owner, named.get("owner"));

        assertThrows(IllegalArgumentException.class,
                () -> GocryptFsProvider.ownerAttributes(owner, "owner:size"));
        assertThrows(UnsupportedOperationException.class,
                () -> GocryptFsProvider.ownerAttributes(owner, "posix:owner"));
    }
}
