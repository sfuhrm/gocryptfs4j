package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.file.NotDirectoryException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Resolves plaintext paths to ciphertext paths and validates path components.
 *
 * <p>Walks a plaintext absolute path component by component, encrypting each
 * name under the IV of the directory that contains it, and verifying that
 * intermediate components are real directories rather than symlinks (which
 * could otherwise escape the cipher root). The result of a resolution is a
 * {@link Resolved}.</p>
 */
final class PathResolver {

    /** Result of resolving a plaintext path to a cipher-side path. */
    static final class Resolved {
        /** The ciphertext-side name. */
        public final String cipherPath;
        /** The ciphertext-side parent name, or {@code null} for the root. */
        public final @Nullable String cipherParent;
        /** The 16-byte IV of the parent directory. */
        public final byte[] parentDirIV;
        /** The ciphertext (encrypted) name, or {@code null} for the root. */
        public final @Nullable String cipherName;
        /** The plaintext (decrypted) name. */
        public final String plainName;

        /**
         * Creates a resolution result.
         *
         * @param cipherPath   the ciphertext-side name
         * @param cipherParent the ciphertext-side parent name, or {@code null} for the root
         * @param parentDirIV  the 16-byte IV of the parent directory
         * @param cipherName   the ciphertext (encrypted) name, or {@code null} for the root
         * @param plainName    the plaintext (decrypted) name
         */
        Resolved(String cipherPath, @Nullable String cipherParent, byte[] parentDirIV,
                 @Nullable String cipherName, String plainName) {
            this.cipherPath = cipherPath;
            this.cipherParent = cipherParent;
            this.parentDirIV = parentDirIV;
            this.cipherName = cipherName;
            this.plainName = plainName;
        }
    }

    /** The ciphertext-side store. */
    private final CipherStore store;

    /** The ciphertext root name. */
    private final String rootName;

    /** Whether file names are stored unencrypted. */
    private final boolean plaintextNames;

    /** The name manager. */
    private final NameManager nameManager;

    /** The directory manager. */
    private final DirectoryManager directoryManager;

    /**
     * Creates a path resolver.
     *
     * @param store            the ciphertext-side store
     * @param rootName         the ciphertext root name
     * @param plaintextNames   whether file names are stored unencrypted
     * @param nameManager      the name manager
     * @param directoryManager the directory manager
     * @throws NullPointerException if a required argument is {@code null}
     */
    PathResolver(CipherStore store, String rootName, boolean plaintextNames,
                 NameManager nameManager, DirectoryManager directoryManager) {
        this.store = Objects.requireNonNull(store, "store");
        this.rootName = Objects.requireNonNull(rootName, "rootName");
        this.plaintextNames = plaintextNames;
        this.nameManager = Objects.requireNonNull(nameManager, "nameManager");
        this.directoryManager = Objects.requireNonNull(directoryManager, "directoryManager");
    }

    /**
     * Resolves a plaintext absolute path (for example {@code "/a/b.txt"}) to its
     * cipher path.
     *
     * @param plainPath the plaintext absolute path
     * @return the resolution result
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     * @throws IllegalArgumentException if the path contains a {@code ..} component
     *                                  or targets a reserved gocryptfs name
     */
    Resolved resolve(String plainPath) throws IOException {
        return resolve(plainPath, false);
    }

    Resolved resolve(String plainPath, boolean create) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        List<String> comps = normalize(plainPath);
        checkNotReserved(comps);
        String cur = rootName;
        byte[] curIV = directoryManager.readDirIV(cur, create);
        for (int i = 0; i < comps.size() - 1; i++) {
            String cName = nameManager.cipherNameFor(comps.get(i), curIV);
            cur = join(cur, cName);
            checkIntermediateDirectory(cur);
            curIV = directoryManager.readDirIV(cur, create);
        }
        if (comps.isEmpty()) {
            return new Resolved(rootName, null, curIV, null, "");
        }
        String plainName = comps.get(comps.size() - 1);
        String cName = nameManager.cipherNameFor(plainName, curIV);
        return new Resolved(join(cur, cName), cur, curIV, cName, plainName);
    }

    /**
     * Resolves the parent directory and basename of a plaintext path.
     *
     * @param plainPath the plaintext path
     * @return the resolution result for the path's final component
     * @throws IOException if the path is empty or the parent cannot be resolved
     */
    Resolved resolveParent(String plainPath) throws IOException {
        return resolveParent(plainPath, false);
    }

    Resolved resolveParent(String plainPath, boolean create) throws IOException {
        List<String> comps = normalize(plainPath);
        checkNotReserved(comps);
        if (comps.isEmpty()) {
            throw new IOException("invalid path: " + plainPath);
        }
        String plainName = comps.remove(comps.size() - 1);
        String cur = rootName;
        byte[] curIV = directoryManager.readDirIV(cur, create);
        for (String c : comps) {
            String cName = nameManager.cipherNameFor(c, curIV);
            cur = join(cur, cName);
            checkIntermediateDirectory(cur);
            curIV = directoryManager.readDirIV(cur, create);
        }
        String cName = nameManager.cipherNameFor(plainName, curIV);
        return new Resolved(join(cur, cName), cur, curIV, cName, plainName);
    }

    /**
     * Verifies that an intermediate path component is a real directory, not a
     * symbolic link. Following a symlink here would allow escaping the cipher
     * root (for example in plaintext-names mode, where a symlink such as
     * {@code /l -> /etc} could redirect writes outside the root).
     *
     * @param dir the resolved intermediate component
     * @throws NotDirectoryException if {@code dir} is not a directory or is a
     *                               symbolic link
     */
    private void checkIntermediateDirectory(String dir) throws IOException {
        if (!store.stat(dir).isDirectory()) {
            throw new NotDirectoryException(dir);
        }
    }

    /**
     * Rejects a plaintext path that would map to a reserved gocryptfs name.
     *
     * <p>Encrypted file names are base64url and can never equal a control-file
     * name (which contains a dot), so the collision only exists in
     * plaintext-names mode, where the cipher name equals the plaintext name.
     * At the root the whole {@code gocryptfs.} prefix is reserved, which covers
     * the config file, its backup, and the per-directory IV. Hidden internal
     * names starting with {@code .gocryptfs} are reserved in every directory.
     * Other same-named entries in a subdirectory remain ordinary files.</p>
     *
     * @param comps the normalized plaintext path components
     * @throws IllegalArgumentException if the path targets a reserved name
     */
    private void checkNotReserved(List<String> comps) {
        if (!plaintextNames) {
            return;
        }
        for (int i = 0; i < comps.size(); i++) {
            String component = comps.get(i);
            if (nameManager.isReservedName(component, i == 0)) {
                throw new IllegalArgumentException("reserved gocryptfs name: " + component);
            }
        }
    }

    /**
     * Splits and normalizes a plaintext path into its components.
     *
     * @param path the plaintext path
     * @return the path components, without empty, {@code "."} or {@code ".."} parts
     * @throws IllegalArgumentException if the path contains a {@code ".."} component
     */
    static List<String> normalize(String path) {
        List<String> out = new ArrayList<>();
        if (path == null || path.isEmpty() || path.equals("/")) {
            return out;
        }
        for (String seg : path.split("/", -1)) {
            if (seg.isEmpty() || seg.equals(".")) {
                continue;
            }
            if (seg.equals("..")) {
                throw new IllegalArgumentException("'..' is not supported: " + path);
            }
            out.add(seg);
        }
        return out;
    }

    /**
     * Joins a ciphertext parent name and a single child name with a slash.
     *
     * @param parent the parent name
     * @param child  the child name
     * @return the joined name
     */
    static String join(String parent, String child) {
        return parent.isEmpty() ? child : parent + "/" + child;
    }

    /**
     * Returns the base name of a ciphertext root name (the part after the last
     * {@code '/'} or {@code '\'}), used as the default FIDO2 registration user
     * name.
     *
     * @param root the root name
     * @return the base name
     */
    static String baseName(String root) {
        int idx = Math.max(root.lastIndexOf('/'), root.lastIndexOf('\\'));
        return idx < 0 ? root : root.substring(idx + 1);
    }
}
