package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.names.NameTransform;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileSystemException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests {@link NameManager} in isolation: the EME name mapping, long-name
 * support-file handling and plaintext-name validation.
 */
class NameManagerTest {

    private static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    @Test
    void plaintextNamesPassThroughUnchanged() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        byte[] iv = new byte[16];

        assertEquals("hello.txt", h.nameManager.cipherNameFor("hello.txt", iv));
        assertEquals("hello.txt", h.nameManager.plainNameFor("hello.txt", iv));
    }

    @Test
    void cipherNameRoundTripsThroughPlainName() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] iv = h.directoryManager.readDirIV(h.store.root());

        String cipher = h.nameManager.cipherNameFor("hello.txt", iv);

        assertNotEquals("hello.txt", cipher);
        assertEquals("hello.txt", h.nameManager.plainNameFor(cipher, iv));
    }

    @Test
    void cipherNameForRejectsOverlyLongName() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] iv = h.directoryManager.readDirIV(h.store.root());

        assertThrows(FileSystemException.class,
                () -> h.nameManager.cipherNameFor(repeat('a', 256), iv));
    }

    @Test
    void isValidPlainNameAcceptsOrdinaryNames() {
        assertTrue(NameManager.isValidPlainName("a"));
        assertTrue(NameManager.isValidPlainName("hello world.txt"));
        assertTrue(NameManager.isValidPlainName("über"));
    }

    @Test
    void isValidPlainNameRejectsUnsafeNames() {
        assertFalse(NameManager.isValidPlainName(""));
        assertFalse(NameManager.isValidPlainName("."));
        assertFalse(NameManager.isValidPlainName(".."));
        assertFalse(NameManager.isValidPlainName("a/b"));
        assertFalse(NameManager.isValidPlainName("a\\b"));
        assertFalse(NameManager.isValidPlainName("a\u0000b"));
    }

    @Test
    void nameTypeClassifiesLongNames() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();

        assertEquals(NameTransform.LONG_NAME_CONTENT,
                h.nameManager.nameType("gocryptfs.longname.abc"));
        assertEquals(NameTransform.LONG_NAME_FILENAME,
                h.nameManager.nameType("gocryptfs.longname.abc.name"));
        assertEquals(NameTransform.LONG_NAME_NONE,
                h.nameManager.nameType("ordinary"));
    }

    @Test
    void longNameRoundTripsThroughSupportFile() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] iv = h.directoryManager.readDirIV(h.store.root());
        String plain = repeat('a', 200);
        String cipher = h.nameManager.cipherNameFor(plain, iv);

        assertTrue(h.nameManager.isLongContent(cipher));

        PathResolver.Resolved r = new PathResolver.Resolved(
                PathResolver.join(h.store.root(), cipher), h.store.root(), iv, cipher, plain);
        assertTrue(h.nameManager.prepareLongName(r));

        String resolved = h.nameManager.resolveLongName(h.store.root(), cipher);
        assertEquals(plain, h.nameManager.plainNameFor(resolved, iv));

        h.nameManager.removeLongName(r);
        assertThrows(IOException.class,
                () -> h.nameManager.resolveLongName(h.store.root(), cipher));
    }

    @Test
    void prepareLongNameReturnsFalseForOrdinaryNames() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] iv = h.directoryManager.readDirIV(h.store.root());
        String cipher = h.nameManager.cipherNameFor("short.txt", iv);

        PathResolver.Resolved r = new PathResolver.Resolved(
                PathResolver.join(h.store.root(), cipher), h.store.root(), iv, cipher, "short.txt");
        assertFalse(h.nameManager.isLongContent(cipher));
        assertFalse(h.nameManager.prepareLongName(r));
    }
}
