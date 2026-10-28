package de.sfuhrm.gocryptfs4j.config;

import com.google.gson.annotations.SerializedName;

/**
 * The scrypt parameters stored in {@code gocryptfs.conf}.
 */
public final class ScryptKdf {

    /** Creates an empty scrypt parameter object (used by Gson). */
    @SuppressWarnings("NullAway.Init")
    public ScryptKdf() {
    }

    /**
     * Creates a scrypt parameter object.
     *
     * @param salt   the base64-encoded salt
     * @param n      the CPU/memory cost parameter (2^LogN)
     * @param r      the block size parameter
     * @param p      the parallelization parameter
     * @param keyLen the output key length in bytes
     */
    public ScryptKdf(String salt, int n, int r, int p, int keyLen) {
        this.salt = salt;
        this.n = n;
        this.r = r;
        this.p = p;
        this.keyLen = keyLen;
    }

    /** Base64-encoded salt. */
    @SerializedName("Salt")
    private String salt;

    /** CPU/memory cost parameter (2^LogN). */
    @SerializedName("N")
    private int n;

    /** Block size parameter. */
    @SerializedName("R")
    private int r;

    /** Parallelization parameter. */
    @SerializedName("P")
    private int p;

    /** Output key length in bytes. */
    @SerializedName("KeyLen")
    private int keyLen;

    /**
     * Returns the base64-encoded salt.
     *
     * @return the base64-encoded salt
     */
    public String salt() {
        return salt;
    }

    /**
     * Returns the CPU/memory cost parameter (2^LogN).
     *
     * @return the cost parameter
     */
    public int n() {
        return n;
    }

    /**
     * Returns the block size parameter.
     *
     * @return the block size parameter
     */
    public int r() {
        return r;
    }

    /**
     * Returns the parallelization parameter.
     *
     * @return the parallelization parameter
     */
    public int p() {
        return p;
    }

    /**
     * Returns the output key length in bytes.
     *
     * @return the output key length in bytes
     */
    public int keyLen() {
        return keyLen;
    }
}
