package de.sfuhrm.gocryptfs4j.store.local;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * An exclusive lock for one local ciphertext root directory.
 *
 * <p>The lock is an atomic create of a hidden file inside the ciphertext root,
 * combined with a JVM-wide registry keyed by the canonical root path. The
 * registry catches a second writer in the same JVM, and the atomically created
 * file extends the protection to other processes. File creation is used instead
 * of an advisory file lock because advisory locks are silently ineffective on
 * some network and cloud-backed filesystems.</p>
 *
 * <p>The lock file lives inside the root (and is ignored by listings and create
 * emptiness checks as an internal name), so opening a writable filesystem does
 * not require write permission on the parent directory and does not leave files
 * next to the vault. It is removed on close. A lock file left behind by a
 * crashed process is reclaimed when its owner was on this host and is no longer
 * alive; a lock file from another host is kept, because a crash cannot be
 * distinguished from a live writer without a working distributed lock.</p>
 */
final class RootFileLock implements AutoCloseable {

    /** The name of the lock file inside the ciphertext root. */
    static final String LOCK_FILE_NAME = ".gocryptfs.lock";

    /** Maximum size of the lock-file metadata accepted when reading it. */
    private static final int MAX_LOCK_FILE_SIZE = 4096;

    /** The first line of a lock file written by this implementation. */
    private static final String LOCK_FILE_HEADER = "gocryptfs4j lock v1";

    /**
     * How long a malformed or empty lock file has to exist before it is
     * considered left behind by a crash during lock-file creation.
     */
    private static final long ORPHAN_GRACE_MILLIS = 60_000L;

    /** The roots currently locked by this JVM. */
    private static final ConcurrentHashMap<String, Boolean> JVM_LOCKS =
            new ConcurrentHashMap<>();

    /** The host name used to decide whether a lock owner can be checked. */
    private static final String LOCAL_HOST = localHostName();

    /** The PID of this process, or {@code -1} when it cannot be determined. */
    private static final long LOCAL_PID = currentPid();

    /** The canonical root key in {@link #JVM_LOCKS}. */
    private final String key;

    /** The lock file inside the ciphertext root. */
    private final Path lockFile;

    /** The random token stored in this instance's lock file. */
    private final String token;

    /** Guards {@link #close()} so it is idempotent. */
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Creates a lock handle.
     *
     * @param key      the canonical root key
     * @param lockFile the lock file
     * @param token    the token stored in the lock file
     */
    private RootFileLock(String key, Path lockFile, String token) {
        this.key = key;
        this.lockFile = lockFile;
        this.token = token;
    }

    /**
     * Acquires the lock for a local ciphertext root.
     *
     * @param root the canonical ciphertext root directory
     * @return the acquired lock
     * @throws IOException if the root is already locked or the lock file cannot
     *                     be created
     * @throws NullPointerException if {@code root} is {@code null}
     */
    static RootFileLock acquire(Path root) throws IOException {
        Objects.requireNonNull(root, "root");
        String key = root.toString();
        if (JVM_LOCKS.putIfAbsent(key, Boolean.TRUE) != null) {
            throw new IOException("cipher directory is already open for writing: " + key);
        }
        Path lockFile = root.resolve(LOCK_FILE_NAME);
        String token = UUID.randomUUID().toString();
        boolean ok = false;
        try {
            for (int attempt = 0; attempt < 4; attempt++) {
                try (FileChannel channel = FileChannel.open(lockFile,
                        StandardOpenOption.CREATE_NEW,
                        StandardOpenOption.READ,
                        StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS)) {
                    try {
                        writeOwner(channel, token);
                    } catch (IOException e) {
                        deleteLockFileQuietly(lockFile, e);
                        throw e;
                    }
                    RootFileLock lock = new RootFileLock(key, lockFile, token);
                    ok = true;
                    return lock;
                } catch (FileAlreadyExistsException e) {
                    if (reclaimIfStale(lockFile)) {
                        continue;
                    }
                    throw new IOException(
                            "cipher directory is locked by another process: " + key, e);
                }
            }
            throw new IOException("could not acquire the cipher directory lock: " + key);
        } finally {
            if (!ok) {
                JVM_LOCKS.remove(key);
            }
        }
    }

    /**
     * Writes this process's identity and a random token into the lock file.
     *
     * @param channel the newly created lock-file channel
     * @param token   the random token for this lock
     * @throws IOException if the metadata cannot be written
     */
    private static void writeOwner(FileChannel channel, String token) throws IOException {
        String data = LOCK_FILE_HEADER
                + "\nhost=" + LOCAL_HOST
                + "\npid=" + LOCAL_PID
                + "\ntoken=" + token
                + "\n";
        ByteBuffer buffer = ByteBuffer.wrap(data.getBytes(StandardCharsets.UTF_8));
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
        try {
            // The lock is the file's existence, not its durability. Some
            // network and cloud filesystems do not support forcing a file.
            channel.force(true);
        } catch (IOException | RuntimeException ignored) {
            // Keep the lock; a crash may leave the metadata incomplete, which
            // is handled as an orphaned lock after a grace period.
        }
    }

    /**
     * Deletes a partially created lock file, keeping the original failure.
     *
     * @param lockFile the lock file to delete
     * @param failure  the failure that caused the deletion
     */
    private static void deleteLockFileQuietly(Path lockFile, IOException failure) {
        try {
            Files.deleteIfExists(lockFile);
        } catch (IOException e) {
            failure.addSuppressed(e);
        }
    }

    /**
     * Reclaims a lock file whose owner is known to be gone.
     *
     * <p>The metadata is read again immediately before deletion so that a lock
     * file created by another process in the meantime is not removed.</p>
     *
     * @param lockFile the existing lock file
     * @return {@code true} if the file was stale and has been removed
     * @throws IOException if the lock file cannot be read or deleted
     */
    private static boolean reclaimIfStale(Path lockFile) throws IOException {
        Owner stale;
        try {
            stale = readOwner(lockFile);
        } catch (NoSuchFileException e) {
            return true;
        }
        if (!isStale(stale)) {
            return false;
        }
        Owner current;
        try {
            current = readOwner(lockFile);
        } catch (NoSuchFileException e) {
            return true;
        }
        if (!stale.sameLock(current)) {
            return false;
        }
        try {
            Files.delete(lockFile);
        } catch (NoSuchFileException e) {
            // Another process removed it first; the next attempt can create it.
        }
        return true;
    }

    /**
     * Returns whether a lock owner is definitely gone.
     *
     * <p>Only a malformed file old enough to outlive the creation window, or a
     * process on this host that is no longer alive, is considered stale. A
     * lock owned by another host is never reclaimed automatically.</p>
     *
     * @param owner the parsed lock owner
     * @return whether the lock can safely be reclaimed
     */
    private static boolean isStale(Owner owner) {
        long age = System.currentTimeMillis() - owner.lastModified;
        if (!owner.valid) {
            return age > ORPHAN_GRACE_MILLIS;
        }
        if (!owner.host.equalsIgnoreCase(LOCAL_HOST)) {
            return false;
        }
        return !isProcessAlive(owner.pid);
    }

    /**
     * Reads and parses the lock-file owner metadata.
     *
     * @param lockFile the lock file
     * @return the parsed owner, or an invalid owner for an empty or malformed file
     * @throws IOException if the file cannot be read
     */
    private static Owner readOwner(Path lockFile) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(lockFile,
                BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        long lastModified = attributes.lastModifiedTime().toMillis();
        if (!attributes.isRegularFile()
                || attributes.size() > MAX_LOCK_FILE_SIZE) {
            return Owner.invalid(lastModified);
        }
        String text = new String(Files.readAllBytes(lockFile), StandardCharsets.UTF_8);
        String[] lines = text.split("\n");
        if (lines.length < 2 || !LOCK_FILE_HEADER.equals(lines[0])) {
            return Owner.invalid(lastModified);
        }
        String host = null;
        String token = null;
        long pid = -1;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.startsWith("host=")) {
                host = line.substring("host=".length());
            } else if (line.startsWith("pid=")) {
                try {
                    pid = Long.parseLong(line.substring("pid=".length()));
                } catch (NumberFormatException e) {
                    return Owner.invalid(lastModified);
                }
            } else if (line.startsWith("token=")) {
                token = line.substring("token=".length());
            }
        }
        if (host == null || host.isEmpty() || token == null || token.isEmpty()
                || pid < 0) {
            return Owner.invalid(lastModified);
        }
        return new Owner(true, host, pid, token, lastModified);
    }

    /**
     * Returns whether a process with the given id is still alive.
     *
     * <p>{@code ProcessHandle} is used reflectively so this class still builds
     * and runs on Java 8. When liveness cannot be checked, the process is
     * treated as alive (fail closed).</p>
     *
     * @param pid the process id
     * @return whether the process is alive
     */
    private static boolean isProcessAlive(long pid) {
        if (pid <= 0) {
            return true;
        }
        try {
            Class<?> processHandle = Class.forName("java.lang.ProcessHandle");
            Object optional = processHandle.getMethod("of", long.class)
                    .invoke(null, pid);
            Class<?> optionalType = Class.forName("java.util.Optional");
            if (!(Boolean) optionalType.getMethod("isPresent").invoke(optional)) {
                return false;
            }
            Object handle = optionalType.getMethod("get").invoke(optional);
            return (Boolean) processHandle.getMethod("isAlive").invoke(handle);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return true;
        }
    }

    /**
     * Returns the PID of this process.
     *
     * @return the PID, or {@code -1} when it cannot be determined
     */
    private static long currentPid() {
        try {
            Class<?> processHandle = Class.forName("java.lang.ProcessHandle");
            Object current = processHandle.getMethod("current").invoke(null);
            return ((Number) processHandle.getMethod("pid").invoke(current)).longValue();
        } catch (ReflectiveOperationException | RuntimeException e) {
            // Fall back to the HotSpot-style runtime name on Java 8.
        }
        try {
            String name = ManagementFactory.getRuntimeMXBean().getName();
            int at = name.indexOf('@');
            return Long.parseLong(at < 0 ? name : name.substring(0, at));
        } catch (RuntimeException e) {
            return -1;
        }
    }

    /**
     * Returns the local host name, or the empty string when unavailable.
     *
     * @return the local host name
     */
    private static String localHostName() {
        String name = System.getenv("HOSTNAME");
        if (name == null || name.isEmpty()) {
            name = System.getenv("COMPUTERNAME");
        }
        if (name != null && !name.isEmpty()) {
            return name;
        }
        try {
            name = InetAddress.getLocalHost().getHostName();
            if (name != null && !name.isEmpty()) {
                return name;
            }
        } catch (IOException | RuntimeException e) {
            // Fall through to the runtime name.
        }
        try {
            String runtimeName = ManagementFactory.getRuntimeMXBean().getName();
            int at = runtimeName.indexOf('@');
            if (at >= 0 && at + 1 < runtimeName.length()) {
                return runtimeName.substring(at + 1);
            }
        } catch (RuntimeException e) {
            // Fall through to the sentinel.
        }
        return "unknown";
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        IOException failure = null;
        try {
            Owner owner = readOwner(lockFile);
            if (owner.valid && token.equals(owner.token)) {
                Files.deleteIfExists(lockFile);
            }
        } catch (NoSuchFileException e) {
            // The lock file is already gone.
        } catch (IOException e) {
            failure = e;
        } finally {
            JVM_LOCKS.remove(key);
        }
        if (failure != null) {
            throw failure;
        }
    }

    /**
     * The identity stored in a lock file.
     */
    private static final class Owner {

        /** Whether the metadata could be parsed. */
        private final boolean valid;

        /** The owner's host name. */
        private final String host;

        /** The owner's process id. */
        private final long pid;

        /** The random lock token. */
        private final String token;

        /** The lock file's last-modified timestamp. */
        private final long lastModified;

        /**
         * Creates an owner record.
         *
         * @param valid        whether the metadata is valid
         * @param host         the owner's host name
         * @param pid          the owner's process id
         * @param token        the lock token
         * @param lastModified the lock file's last-modified timestamp
         */
        private Owner(boolean valid, String host, long pid, String token,
                      long lastModified) {
            this.valid = valid;
            this.host = host;
            this.pid = pid;
            this.token = token;
            this.lastModified = lastModified;
        }

        /**
         * Creates an invalid owner record for a malformed lock file.
         *
         * @param lastModified the lock file's last-modified timestamp
         * @return an invalid owner
         */
        private static Owner invalid(long lastModified) {
            return new Owner(false, "", -1, "", lastModified);
        }

        /**
         * Returns whether two reads refer to the same lock-file content.
         *
         * @param other the other owner record
         * @return whether the records are the same lock
         */
        private boolean sameLock(Owner other) {
            if (valid != other.valid) {
                return false;
            }
            if (!valid) {
                return lastModified == other.lastModified;
            }
            return token.equals(other.token);
        }
    }
}
