package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.util.Objects;

/**
 * Encrypts and decrypts file names and manages long-name support files.
 *
 * <p>Owns the {@link NameTransform} helper (EME wide-block name encryption) and
 * all logic that depends on how names are stored: the plaintext-names
 * pass-through, the cipher-name mapping used by {@link PathResolver} and
 * {@link DirectoryManager}, and the {@code gocryptfs.longname.*.name} support
 * files that hold the full cipher name of a hashed long name.</p>
 */
final class NameManager {

    /** The name-transform helper. */
    private final NameTransform nameTransform;

    /** Whether file names are stored unencrypted. */
    private final boolean plaintextNames;

    /** The ciphertext-side store. */
    private final CipherStore store;

    /**
     * Creates a name manager.
     *
     * @param nameTransform  the name-transform helper
     * @param plaintextNames whether file names are stored unencrypted
     * @param store          the ciphertext-side store
     * @throws NullPointerException if {@code nameTransform} or {@code store} is {@code null}
     */
    NameManager(NameTransform nameTransform, boolean plaintextNames, CipherStore store) {
        this.nameTransform = Objects.requireNonNull(nameTransform, "nameTransform");
        this.plaintextNames = plaintextNames;
        this.store = Objects.requireNonNull(store, "store");
    }

    /**
     * Returns whether file names are stored unencrypted.
     *
     * @return true if file names are stored unencrypted
     */
    boolean plaintextNames() {
        return plaintextNames;
    }

    /**
     * Encrypts (and possibly hashes) a plaintext name using {@code dirIV}.
     *
     * @param plainName the plaintext name
     * @param dirIV     the 16-byte directory IV
     * @return the ciphertext name
     * @throws NullPointerException if {@code plainName} or {@code dirIV} is {@code null}
     * @throws FileSystemException if {@code plainName} is longer than the 255-byte
     *                             name limit
     */
    String cipherNameFor(String plainName, byte[] dirIV) throws IOException {
        Objects.requireNonNull(plainName, "plainName");
        Objects.requireNonNull(dirIV, "dirIV");
        if (plainName.getBytes(StandardCharsets.UTF_8).length > Constants.NAME_MAX) {
            throw new FileSystemException(plainName, null, "File name too long");
        }
        if (plaintextNames) {
            return plainName;
        }
        return nameTransform.encryptAndHashName(plainName, dirIV);
    }

    /**
     * Decrypts a cipher name using {@code dirIV}.
     *
     * @param cipherName the ciphertext name
     * @param dirIV      the 16-byte directory IV
     * @return the plaintext name
     * @throws NullPointerException if {@code cipherName} or {@code dirIV} is {@code null}
     */
    String plainNameFor(String cipherName, byte[] dirIV) {
        Objects.requireNonNull(cipherName, "cipherName");
        Objects.requireNonNull(dirIV, "dirIV");
        if (plaintextNames) {
            return cipherName;
        }
        return nameTransform.decryptName(cipherName, dirIV);
    }

    /**
     * Encrypts a plaintext name under {@code dirIV} without hashing.
     *
     * @param plainName the plaintext name
     * @param dirIV     the 16-byte directory IV
     * @return the full (unhashed) ciphertext name
     * @throws NullPointerException if {@code plainName} or {@code dirIV} is {@code null}
     */
    String encryptName(String plainName, byte[] dirIV) {
        return nameTransform.encryptName(plainName, dirIV);
    }

    /**
     * Returns the name type of a cipher name.
     *
     * @param cipherName the ciphertext name
     * @return one of {@link NameTransform#LONG_NAME_CONTENT},
     *         {@link NameTransform#LONG_NAME_FILENAME} or
     *         {@link NameTransform#LONG_NAME_NONE}
     */
    int nameType(String cipherName) {
        return nameTransform.nameType(cipherName);
    }

    /**
     * Returns whether {@code cipherName} is a long-name content store.
     *
     * @param cipherName the ciphertext name
     * @return true if {@code cipherName} is a long-name content store
     */
    boolean isLongContent(String cipherName) {
        return nameTransform.isLongContent(cipherName);
    }

    /**
     * Reads the full cipher name stored in the long-name support file of
     * {@code cipherName}.
     *
     * @param cipherDir  the ciphertext directory holding the entry
     * @param cipherName the hashed long-name content store
     * @return the full cipher name stored in the {@code .name} support file
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} or {@code cipherName} is {@code null}
     */
    String resolveLongName(String cipherDir, String cipherName) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        Objects.requireNonNull(cipherName, "cipherName");
        String nameFile = PathResolver.join(cipherDir, cipherName + Constants.LONG_NAME_SUFFIX);
        byte[] nameBytes = store.readSmall(nameFile, Constants.LONG_NAME_CONTENT_MAX_SIZE);
        return new String(nameBytes, StandardCharsets.UTF_8);
    }

    /**
     * Writes the long-name support file if the cipher name is a long name.
     *
     * @param r the resolved path whose long-name support file may be needed
     * @return {@code true} if a new long-name support file was created and the
     *         caller must remove it should the operation that follows fail
     * @throws IOException on filesystem errors
     */
    boolean prepareLongName(PathResolver.Resolved r) throws IOException {
        String cipherName = r.cipherName;
        String cipherParent = r.cipherParent;
        if (plaintextNames || cipherName == null || cipherParent == null
                || !nameTransform.isLongContent(cipherName)) {
            return false;
        }
        String nameFile = PathResolver.join(cipherParent, cipherName + Constants.LONG_NAME_SUFFIX);
        byte[] fullCipher = nameTransform.encryptName(r.plainName, r.parentDirIV)
                .getBytes(StandardCharsets.UTF_8);
        try {
            store.writeSmall(nameFile, fullCipher, false);
            return true;
        } catch (FileAlreadyExistsException ignored) {
            // Allowed on rename/overwrite; the existing file is not ours to remove.
            return false;
        }
    }

    /**
     * Removes the long-name support file (if any) for the resolved ciphertext
     * entry. Used for both files and directories.
     *
     * @param r the resolved path whose long-name support file may be removed
     * @throws IOException on filesystem errors
     */
    void removeLongName(PathResolver.Resolved r) throws IOException {
        String cipherName = r.cipherName;
        String cipherParent = r.cipherParent;
        if (plaintextNames || cipherName == null || cipherParent == null
                || !nameTransform.isLongContent(cipherName)) {
            return;
        }
        FileManager.deleteIfExists(store,
                PathResolver.join(cipherParent, cipherName + Constants.LONG_NAME_SUFFIX));
    }

    /**
     * Returns whether a decrypted name is safe to use as a single path
     * component.
     *
     * @param name the decrypted name
     * @return {@code false} if {@code name} is empty, {@code "."}, {@code ".."},
     *         or contains a path separator or NUL byte
     */
    static boolean isValidPlainName(String name) {
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '/' || c == '\\' || c == '\0') {
                return false;
            }
        }
        return true;
    }
}
