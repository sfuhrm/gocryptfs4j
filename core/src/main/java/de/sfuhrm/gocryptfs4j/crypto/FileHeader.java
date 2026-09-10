package de.sfuhrm.gocryptfs4j.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * The per-file header stored at the start of every non-empty file:
 * {@code [version uint16 BE][id 16 random bytes]}.
 */
public final class FileHeader {

    private final int version;
    private final byte[] id;

    /**
     * Creates a file header.
     *
     * @param version the on-disk format version
     * @param id      the 16-byte random file id
     * @throws NullPointerException if {@code id} is {@code null}
     * @throws IllegalArgumentException if {@code id} is not 16 bytes long
     */
    public FileHeader(int version, byte[] id) {
        Objects.requireNonNull(id, "id");
        if (id.length != Constants.HEADER_ID_LEN) {
            throw new IllegalArgumentException("file id must be " + Constants.HEADER_ID_LEN + " bytes");
        }
        this.version = version;
        this.id = id;
    }

    /**
     * Creates a new header with a random 128-bit file id.
     *
     * @return the new header
     */
    public static FileHeader random() {
        return new FileHeader(Constants.CURRENT_VERSION, Keys.randomBytes(Constants.HEADER_ID_LEN));
    }

    /**
     * Serializes the header.
     *
     * @return the serialized header
     */
    public byte[] pack() {
        byte[] buf = new byte[Constants.HEADER_LEN];
        buf[0] = (byte) (version >>> 8);
        buf[1] = (byte) version;
        System.arraycopy(id, 0, buf, Constants.HEADER_VERSION_LEN, Constants.HEADER_ID_LEN);
        return buf;
    }

    /**
     * Parses a header.
     *
     * @param buf the serialized header
     * @return the parsed header
     * @throws NullPointerException if {@code buf} is {@code null}
     * @throws IllegalArgumentException if the header is malformed
     */
    public static FileHeader parse(byte[] buf) {
        Objects.requireNonNull(buf, "buf");
        if (buf.length != Constants.HEADER_LEN) {
            throw new IllegalArgumentException("invalid header length: want="
                    + Constants.HEADER_LEN + " have=" + buf.length);
        }
        boolean allZero = true;
        for (byte b : buf) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            throw new IllegalArgumentException("header is all-zero");
        }
        int version = ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);
        if (version != Constants.CURRENT_VERSION) {
            throw new IllegalArgumentException("invalid version: want="
                    + Constants.CURRENT_VERSION + " have=" + version);
        }
        byte[] id = Arrays.copyOfRange(buf, Constants.HEADER_VERSION_LEN, Constants.HEADER_LEN);
        boolean zeroId = true;
        for (byte b : id) {
            if (b != 0) {
                zeroId = false;
                break;
            }
        }
        if (zeroId) {
            throw new IllegalArgumentException("file id is all-zero");
        }
        return new FileHeader(version, id);
    }

    /**
     * Returns the on-disk format version.
     *
     * @return the version
     */
    public int version() {
        return version;
    }

    /**
     * Returns the file id.
     *
     * @return the 16-byte file id
     */
    public byte[] id() {
        return id;
    }
}
