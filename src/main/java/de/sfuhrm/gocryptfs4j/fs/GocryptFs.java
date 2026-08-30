package de.sfuhrm.gocryptfs4j.fs;

import de.sfuhrm.gocryptfs4j.config.ConfigFile;
import de.sfuhrm.gocryptfs4j.crypto.AesBlockCipher;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentCipherType;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Eme;
import de.sfuhrm.gocryptfs4j.crypto.Hkdf;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.names.NameTransform;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * A Java API to a gocryptfs cipher directory.
 *
 * <p>Provides traversal, listing and content read/write on the plaintext view of
 * an encrypted directory using the gocryptfs forward-mode on-disk format.</p>
 *
 * <pre>{@code
 * try (GocryptFs fs = GocryptFs.open(Path.of("/data/cipher"), "password")) {
 *     for (DirEntry e : fs.list("/")) {
 *         System.out.println(e.plainName());
 *     }
 *     byte[] content = fs.readAll("/notes.txt");
 * }
 * }</pre>
 */
public final class GocryptFs implements AutoCloseable {

    private final Path cipherRoot;
    private final ConfigFile config;
    private final byte[] masterKey;
    private final Eme eme;
    private final ContentEnc contentEnc;
    private final NameTransform nameTransform;
    private final boolean plaintextNames;
    private final boolean dirIvFlag;
    private final boolean deterministicNames;

    private GocryptFs(Path cipherRoot, ConfigFile config, byte[] masterKey) {
        this.cipherRoot = cipherRoot.toAbsolutePath().normalize();
        this.config = config;
        this.masterKey = masterKey;
        this.plaintextNames = config.plaintextNames();
        this.dirIvFlag = config.dirIv();
        this.deterministicNames = !plaintextNames && !dirIvFlag;

        boolean useHkdf = config.hkdf();
        byte[] emeKey = useHkdf
                ? Hkdf.derive(masterKey, Constants.HKDF_INFO_EME_NAMES, Constants.KEY_LEN)
                : Arrays.copyOf(masterKey, masterKey.length);
        this.eme = new Eme(new AesBlockCipher(emeKey));
        this.contentEnc = config.contentEnc(masterKey);
        this.nameTransform = new NameTransform(eme, config.longNames(), config.longNameMax(),
                config.raw64(), deterministicNames);
    }

    /**
     * Opens an existing cipher directory, unlocking the master key from
     * {@code password}.
     *
     * @param cipherDir the ciphertext directory
     * @param password  the password to unlock the master key with
     * @return the opened filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     */
    public static GocryptFs open(Path cipherDir, char[] password) throws IOException {
        Path confPath = cipherDir.resolve(Constants.CONF_DEFAULT_NAME);
        ConfigFile config = ConfigFile.load(confPath);
        byte[] masterKey = config.decryptMasterKey(password);
        return new GocryptFs(cipherDir, config, masterKey);
    }

    /**
     * Opens an existing cipher directory, unlocking the master key from
     * {@code password}.
     *
     * @param cipherDir the ciphertext directory
     * @param password  the password to unlock the master key with
     * @return the opened filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     */
    public static GocryptFs open(Path cipherDir, String password) throws IOException {
        return open(cipherDir, password.toCharArray());
    }

    /**
     * Creates a new gocryptfs filesystem in {@code cipherDir} (which must exist
     * and be empty) and opens it.
     *
     * @param cipherDir the ciphertext directory (must exist and be empty)
     * @param password  the password to protect the master key with
     * @return the opened filesystem
     * @throws IOException on filesystem errors
     */
    public static GocryptFs create(Path cipherDir, char[] password) throws IOException {
        return create(cipherDir, password, false);
    }

    /**
     * Creates a new filesystem, optionally with plaintext (unencrypted) names.
     *
     * @param cipherDir      the ciphertext directory (must exist and be empty)
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @return the opened filesystem
     * @throws IOException on filesystem errors
     */
    public static GocryptFs create(Path cipherDir, char[] password, boolean plaintextNames) throws IOException {
        return create(cipherDir, password, plaintextNames, ContentCipherType.AES_GCM);
    }

    /**
     * Creates a new filesystem, optionally with plaintext (unencrypted) names
     * and a custom content cipher.
     *
     * @param cipherDir      the ciphertext directory (must exist and be empty)
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @return the opened filesystem
     * @throws IOException on filesystem errors
     */
    public static GocryptFs create(Path cipherDir, char[] password, boolean plaintextNames,
                                   ContentCipherType cipherType) throws IOException {
        Path dir = cipherDir.toAbsolutePath().normalize();
        if (!Files.isDirectory(dir)) {
            throw new IOException("cipher dir does not exist: " + dir);
        }
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        ConfigFile config = ConfigFile.create(masterKey, password, plaintextNames, cipherType);
        config.writeTo(dir.resolve(Constants.CONF_DEFAULT_NAME));
        GocryptFs fs = new GocryptFs(dir, config, masterKey);
        try {
            if (!plaintextNames) {
                fs.writeDirIV(dir);
            }
            return fs;
        } catch (IOException e) {
            Files.deleteIfExists(dir.resolve(Constants.CONF_DEFAULT_NAME));
            throw e;
        }
    }

    /**
     * Returns the ciphertext root directory.
     *
     * @return the ciphertext root directory
     */
    public Path cipherRoot() {
        return cipherRoot;
    }

    /**
     * Returns the configuration file.
     *
     * @return the configuration file
     */
    public ConfigFile config() {
        return config;
    }

    /**
     * Returns the content-encryption helper.
     *
     * @return the content-encryption helper
     */
    public ContentEnc contentEnc() {
        return contentEnc;
    }

    /**
     * Returns the name-transform helper.
     *
     * @return the name-transform helper
     */
    public NameTransform nameTransform() {
        return nameTransform;
    }

    /**
     * Returns whether file names are stored unencrypted.
     *
     * @return true if file names are stored unencrypted
     */
    public boolean plaintextNames() {
        return plaintextNames;
    }

    // ------------------------------------------------------------------
    // Directory IV management
    // ------------------------------------------------------------------

    /**
     * Reads the {@code gocryptfs.diriv} of {@code cipherDir}.
     *
     * @param cipherDir the ciphertext directory
     * @return the 16-byte directory IV
     * @throws IOException on filesystem errors
     */
    public byte[] readDirIV(Path cipherDir) throws IOException {
        if (plaintextNames) {
            return new byte[Constants.DIR_IV_LEN];
        }
        if (deterministicNames) {
            return nameTransform.zeroDirIV();
        }
        Path p = cipherDir.resolve(Constants.DIR_IV_FILENAME);
        byte[] data = Files.readAllBytes(p);
        if (data.length != Constants.DIR_IV_LEN) {
            throw new IOException("bad diriv length " + data.length + " in " + cipherDir);
        }
        for (byte b : data) {
            if (b != 0) {
                return data;
            }
        }
        throw new IOException("diriv is all-zero in " + cipherDir);
    }

    /**
     * Creates a {@code gocryptfs.diriv} in {@code cipherDir}.
     *
     * @param cipherDir the ciphertext directory
     * @throws IOException on filesystem errors
     */
    public void writeDirIV(Path cipherDir) throws IOException {
        if (plaintextNames || deterministicNames) {
            return;
        }
        Path p = cipherDir.resolve(Constants.DIR_IV_FILENAME);
        Files.write(p, Keys.randomBytes(Constants.DIR_IV_LEN),
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    // ------------------------------------------------------------------
    // Name mapping
    // ------------------------------------------------------------------

    /**
     * Encrypts (and possibly hashes) a plaintext name using {@code dirIV}.
     *
     * @param plainName the plaintext name
     * @param dirIV     the 16-byte directory IV
     * @return the ciphertext name
     */
    public String cipherNameFor(String plainName, byte[] dirIV) {
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
     */
    public String plainNameFor(String cipherName, byte[] dirIV) {
        if (plaintextNames) {
            return cipherName;
        }
        return nameTransform.decryptName(cipherName, dirIV);
    }

    // ------------------------------------------------------------------
    // Path resolution
    // ------------------------------------------------------------------

    /** Result of resolving a plaintext path to a cipher-side path. */
    public static final class Resolved {
        /** The ciphertext-side path. */
        public final Path cipherPath;
        /** The ciphertext-side parent directory. */
        public final Path cipherParent;
        /** The 16-byte IV of the parent directory. */
        public final byte[] parentDirIV;
        /** The ciphertext (encrypted) name. */
        public final String cipherName;
        /** The plaintext (decrypted) name. */
        public final String plainName;

        Resolved(Path cipherPath, Path cipherParent, byte[] parentDirIV, String cipherName, String plainName) {
            this.cipherPath = cipherPath;
            this.cipherParent = cipherParent;
            this.parentDirIV = parentDirIV;
            this.cipherName = cipherName;
            this.plainName = plainName;
        }
    }

    /**
     * Resolves a plaintext absolute path (e.g. {@code "/a/b.txt"}) to its cipher path.
     *
     * @param plainPath the plaintext absolute path
     * @return the resolution result
     * @throws IOException on filesystem errors
     */
    public Resolved resolve(String plainPath) throws IOException {
        List<String> comps = normalize(plainPath);
        Path cur = cipherRoot;
        byte[] curIV = readDirIV(cur);
        for (int i = 0; i < comps.size() - 1; i++) {
            String cName = cipherNameFor(comps.get(i), curIV);
            cur = cur.resolve(cName);
            curIV = readDirIV(cur);
        }
        if (comps.isEmpty()) {
            return new Resolved(cipherRoot, null, curIV, null, "");
        }
        String plainName = comps.get(comps.size() - 1);
        String cName = cipherNameFor(plainName, curIV);
        return new Resolved(cur.resolve(cName), cur, curIV, cName, plainName);
    }

    /** Resolves the parent directory and basename of a plaintext path. */
    private Resolved resolveParent(String plainPath) throws IOException {
        List<String> comps = normalize(plainPath);
        if (comps.isEmpty()) {
            throw new IOException("invalid path: " + plainPath);
        }
        String plainName = comps.remove(comps.size() - 1);
        Path cur = cipherRoot;
        byte[] curIV = readDirIV(cur);
        for (String c : comps) {
            String cName = cipherNameFor(c, curIV);
            cur = cur.resolve(cName);
            curIV = readDirIV(cur);
        }
        String cName = cipherNameFor(plainName, curIV);
        return new Resolved(cur.resolve(cName), cur, curIV, cName, plainName);
    }

    private static List<String> normalize(String path) {
        List<String> out = new ArrayList<>();
        if (path == null || path.isEmpty() || path.equals("/")) {
            return out;
        }
        for (String seg : path.split("/")) {
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

    // ------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------

    /**
     * Lists a plaintext directory path, returning entries sorted by name.
     *
     * @param plainDir the plaintext directory path
     * @return the directory entries sorted by plaintext name
     * @throws IOException on filesystem errors
     */
    public List<DirEntry> list(String plainDir) throws IOException {
        Resolved r = resolve(plainDir);
        byte[] iv = readDirIV(r.cipherPath);
        List<DirEntry> entries = listCipherDir(r.cipherPath, iv);
        entries.sort(Comparator.comparing(DirEntry::plainName));
        return entries;
    }

    /**
     * Lists a cipher-side directory, decrypting names and resolving long names.
     *
     * @param cipherDir the ciphertext directory
     * @param iv        the 16-byte directory IV
     * @return the directory entries
     * @throws IOException on filesystem errors
     */
    public List<DirEntry> listCipherDir(Path cipherDir, byte[] iv) throws IOException {
        List<DirEntry> out = new ArrayList<>();
        boolean isRoot = cipherDir.equals(cipherRoot);
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(cipherDir)) {
            for (Path p : ds) {
                String cName = p.getFileName().toString();
                if (cName.equals(Constants.DIR_IV_FILENAME)) {
                    continue;
                }
                if (isRoot && cName.equals(Constants.CONF_DEFAULT_NAME)) {
                    continue;
                }

                BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);

                String cipherName = cName;
                if (!plaintextNames) {
                    int t = nameTransform.nameType(cName);
                    if (t == NameTransform.LONG_NAME_FILENAME) {
                        continue;
                    }
                    if (t == NameTransform.LONG_NAME_CONTENT) {
                        Path nameFile = cipherDir.resolve(cName + Constants.LONG_NAME_SUFFIX);
                        cipherName = Files.readString(nameFile, StandardCharsets.UTF_8);
                    }
                }

                String plainName;
                try {
                    plainName = plainNameFor(cipherName, iv);
                } catch (IllegalArgumentException e) {
                    // Skip undecryptable (corrupt) entries.
                    continue;
                }

                DirEntry.Kind kind;
                long size;
                if (attrs.isDirectory()) {
                    kind = DirEntry.Kind.DIRECTORY;
                    size = 0;
                } else if (attrs.isSymbolicLink()) {
                    kind = DirEntry.Kind.SYMLINK;
                    size = readSymlink(p).length();
                } else if (attrs.isRegularFile()) {
                    kind = DirEntry.Kind.FILE;
                    size = contentEnc.cipherSizeToPlainSize(attrs.size());
                } else {
                    kind = DirEntry.Kind.OTHER;
                    size = attrs.size();
                }

                out.add(new DirEntry(plainName, cName, p, kind, size,
                        attrs.lastModifiedTime(), attrs.lastAccessTime(),
                        attrs.creationTime(), attrs.fileKey()));
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Symlinks
    // ------------------------------------------------------------------

    /**
     * Reads and decrypts the target of a cipher-side symlink.
     *
     * @param cipherSymlink the ciphertext symlink path
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     */
    public String readSymlink(Path cipherSymlink) throws IOException {
        String target = Files.readSymbolicLink(cipherSymlink).toString();
        if (plaintextNames) {
            return target;
        }
        if (target.isEmpty()) {
            return "";
        }
        byte[] cData = nameTransform.b64Decode(target);
        try {
            byte[] data = contentEnc.decryptBlock(cData, 0, null);
            return new String(data, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("corrupt symlink target", e);
        }
    }

    /**
     * Reads and decrypts the target of a plaintext symlink path.
     *
     * @param plainPath the plaintext symlink path
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     */
    public String readSymlinkTarget(String plainPath) throws IOException {
        Resolved r = resolve(plainPath);
        return readSymlink(r.cipherPath);
    }

    // ------------------------------------------------------------------
    // Content access
    // ------------------------------------------------------------------

    /**
     * Returns the plaintext attributes of a path (file, directory or symlink).
     *
     * @param plainPath the plaintext path
     * @return the directory entry
     * @throws IOException on filesystem errors
     */
    public DirEntry stat(String plainPath) throws IOException {
        Resolved r = resolve(plainPath);
        return statResolved(r);
    }

    private DirEntry statResolved(Resolved r) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(r.cipherPath, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        DirEntry.Kind kind;
        long size;
        if (attrs.isDirectory()) {
            kind = DirEntry.Kind.DIRECTORY;
            size = 0;
        } else if (attrs.isSymbolicLink()) {
            kind = DirEntry.Kind.SYMLINK;
            size = readSymlink(r.cipherPath).length();
        } else if (attrs.isRegularFile()) {
            kind = DirEntry.Kind.FILE;
            size = contentEnc.cipherSizeToPlainSize(attrs.size());
        } else {
            kind = DirEntry.Kind.OTHER;
            size = attrs.size();
        }
        String plainName = r.plainName.isEmpty() ? "/" : r.plainName;
        return new DirEntry(plainName, r.cipherName, r.cipherPath, kind, size,
                attrs.lastModifiedTime(), attrs.lastAccessTime(), attrs.creationTime(),
                attrs.fileKey());
    }

    /**
     * Opens a cipher-side file for random access.
     *
     * @param cipherFile the ciphertext file path
     * @param writable   whether to open for writing
     * @return the opened cipher file
     * @throws IOException on filesystem errors
     */
    public CipherFile openCipherFile(Path cipherFile, boolean writable) throws IOException {
        return CipherFile.open(cipherFile, contentEnc, writable);
    }

    /**
     * Returns the plaintext size of a file.
     *
     * @param plainFile the plaintext file path
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    public long size(String plainFile) throws IOException {
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFile(r.cipherPath, false)) {
            return cf.plainSize();
        }
    }

    /**
     * Reads the entire plaintext content of a file.
     *
     * @param plainFile the plaintext file path
     * @return the plaintext content
     * @throws IOException on filesystem or decryption errors
     */
    public byte[] readAll(String plainFile) throws IOException {
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFile(r.cipherPath, false)) {
            long size = cf.plainSize();
            if (size > Integer.MAX_VALUE) {
                throw new IOException("file too large to read into memory: " + size);
            }
            byte[] out = new byte[(int) size];
            int pos = 0;
            while (pos < size) {
                int n = cf.read(ByteBuffer.wrap(out, pos, (int) (size - pos)), pos);
                if (n < 0) {
                    break;
                }
                pos += n;
            }
            return Arrays.copyOf(out, pos);
        }
    }

    /**
     * Opens a streaming, decrypting input stream over a plaintext file path.
     *
     * @param plainFile the plaintext file path
     * @return the decrypting input stream
     * @throws IOException on filesystem errors
     */
    public InputStream openRead(String plainFile) throws IOException {
        Resolved r = resolve(plainFile);
        CipherFile cf = openCipherFile(r.cipherPath, false);
        return new CipherInputStream(cf);
    }

    /**
     * Writes {@code data} at plaintext {@code offset} of an existing file.
     *
     * @param plainFile the plaintext file path
     * @param offset    the plaintext offset to write at
     * @param data      the data to write
     * @throws IOException on filesystem or encryption errors
     */
    public void write(String plainFile, long offset, byte[] data) throws IOException {
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFile(r.cipherPath, true)) {
            cf.write(ByteBuffer.wrap(data), offset);
        }
    }

    /**
     * Truncates a plaintext file to {@code newSize} bytes.
     *
     * @param plainFile the plaintext file path
     * @param newSize   the new plaintext size in bytes
     * @throws IOException on filesystem or encryption errors
     */
    public void truncate(String plainFile, long newSize) throws IOException {
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFile(r.cipherPath, true)) {
            cf.truncate(newSize);
        }
    }

    /**
     * Sets the last-modified, last-access and creation times of a path.
     *
     * @param plainPath        the plaintext path
     * @param lastModifiedTime the last-modified time
     * @param lastAccessTime   the last-access time
     * @param createTime       the creation time
     * @throws IOException on filesystem errors
     */
    public void setTimes(String plainPath, FileTime lastModifiedTime, FileTime lastAccessTime,
                         FileTime createTime) throws IOException {
        Resolved r = resolve(plainPath);
        BasicFileAttributeView view = Files.getFileAttributeView(r.cipherPath,
                BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("basic attribute view not supported");
        }
        view.setTimes(lastModifiedTime, lastAccessTime, createTime);
    }

    private static final class CipherInputStream extends InputStream {
        private final CipherFile cf;
        private long pos;

        CipherInputStream(CipherFile cf) {
            this.cf = cf;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = cf.read(ByteBuffer.wrap(one), pos);
            if (n < 0) {
                return -1;
            }
            pos += n;
            return one[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            int n = cf.read(ByteBuffer.wrap(b, off, len), pos);
            if (n < 0) {
                return -1;
            }
            pos += n;
            return n;
        }

        @Override
        public void close() throws IOException {
            cf.close();
        }
    }

    // ------------------------------------------------------------------
    // Create / delete
    // ------------------------------------------------------------------

    /**
     * Creates an empty file (fails if it already exists).
     *
     * @param plainFile the plaintext file path
     * @throws IOException on filesystem errors
     */
    public void createFile(String plainFile) throws IOException {
        Resolved r = resolveParent(plainFile);
        prepareLongName(r);
        Files.createFile(r.cipherPath);
    }

    /**
     * Creates a directory (including its diriv).
     *
     * @param plainDir the plaintext directory path
     * @throws IOException on filesystem errors
     */
    public void mkdir(String plainDir) throws IOException {
        Resolved r = resolveParent(plainDir);
        prepareLongName(r);
        Files.createDirectory(r.cipherPath);
        writeDirIV(r.cipherPath);
    }

    /**
     * Deletes a file, symlink or empty directory.
     *
     * @param plainPath the plaintext path
     * @throws IOException on filesystem errors
     */
    public void delete(String plainPath) throws IOException {
        Resolved r = resolve(plainPath);
        if (Files.isDirectory(r.cipherPath, LinkOption.NOFOLLOW_LINKS)) {
            Files.deleteIfExists(r.cipherPath.resolve(Constants.DIR_IV_FILENAME));
            Files.delete(r.cipherPath);
        } else {
            Files.delete(r.cipherPath);
            if (!plaintextNames && nameTransform.isLongContent(r.cipherName)
                    && r.cipherParent != null) {
                Files.deleteIfExists(r.cipherParent.resolve(r.cipherName + Constants.LONG_NAME_SUFFIX));
            }
        }
    }

    /**
     * Creates a symlink pointing to {@code target}.
     *
     * @param plainPath the plaintext symlink path
     * @param target    the plaintext target
     * @throws IOException on filesystem or encryption errors
     */
    public void createSymlink(String plainPath, String target) throws IOException {
        Resolved r = resolveParent(plainPath);
        prepareLongName(r);
        String cTarget = target;
        if (!plaintextNames && !target.isEmpty()) {
            byte[] enc = contentEnc.encryptBlock(target.getBytes(StandardCharsets.UTF_8), 0, null);
            cTarget = nameTransform.b64Encode(enc);
        }
        Files.createSymbolicLink(r.cipherPath, Path.of(cTarget));
    }

    /** Writes the long-name support file if the cipher name is a long name. */
    private void prepareLongName(Resolved r) throws IOException {
        if (plaintextNames || !nameTransform.isLongContent(r.cipherName)) {
            return;
        }
        Path nameFile = r.cipherParent.resolve(r.cipherName + Constants.LONG_NAME_SUFFIX);
        byte[] fullCipher = nameTransform.encryptName(r.plainName, r.parentDirIV)
                .getBytes(StandardCharsets.UTF_8);
        try {
            Files.write(nameFile, fullCipher,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (FileAlreadyExistsException ignored) {
            // Allowed on rename/overwrite.
        }
    }

    @Override
    public void close() {
        Keys.wipe(masterKey);
    }
}
