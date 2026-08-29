package de.sfuhrm.gocryptfs4j.fs;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.FileHeader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Random-access read/write access to a single encrypted (cipher-side) file.
 *
 * <p>Encapsulates the per-file header (file id) and the block-wise
 * AES-256-GCM content encryption, including read-modify-write for partial
 * block writes.</p>
 */
public final class CipherFile implements AutoCloseable {

    private final FileChannel channel;
    private final ContentEnc enc;
    private byte[] fileId;
    private boolean fileIdLoaded;

    private CipherFile(FileChannel channel, ContentEnc enc) {
        this.channel = channel;
        this.enc = enc;
    }

    public static CipherFile open(Path cipherPath, ContentEnc enc, boolean writable) throws IOException {
        FileChannel ch;
        if (writable) {
            ch = FileChannel.open(cipherPath, StandardOpenOption.READ, StandardOpenOption.WRITE);
        } else {
            ch = FileChannel.open(cipherPath, StandardOpenOption.READ);
        }
        return new CipherFile(ch, enc);
    }

    /** Returns the file id from the header, creating a header if the file is empty and writable. */
    public byte[] fileId() throws IOException {
        if (!fileIdLoaded) {
            long size = channel.size();
            if (size == 0) {
                fileId = null;
            } else {
                byte[] hdr = readCipherRange(0, Constants.HEADER_LEN);
                if (hdr.length < Constants.HEADER_LEN) {
                    throw new IOException("corrupt file header");
                }
                fileId = FileHeader.parse(hdr).id();
            }
            fileIdLoaded = true;
        }
        return fileId;
    }

    /** Returns the plaintext size of the file. */
    public long plainSize() throws IOException {
        long cipherSize = channel.size();
        if (cipherSize == 0) {
            return 0;
        }
        return enc.cipherSizeToPlainSize(cipherSize);
    }

    /**
     * Reads up to {@code dst.remaining()} plaintext bytes at {@code plainOffset}.
     *
     * @return number of bytes read, or -1 if at or past end of file.
     */
    public int read(ByteBuffer dst, long plainOffset) throws IOException {
        long size = plainSize();
        if (plainOffset >= size) {
            return -1;
        }
        int maxLen = dst.remaining();
        if (maxLen == 0) {
            return 0;
        }
        long length = Math.min(maxLen, size - plainOffset);

        byte[] fileId = fileId();
        if (fileId == null) {
            return -1;
        }

        long firstBlock = plainOffset / enc.plainBS;
        int skip = (int) (plainOffset % enc.plainBS);
        long lastBlock = (plainOffset + length - 1) / enc.plainBS;
        long blockCount = lastBlock - firstBlock + 1;

        long cipherOffset = enc.blockNoToCipherOff(firstBlock);
        int cipherLength = (int) (blockCount * enc.cipherBS);
        byte[] ciphertext = readCipherRange(cipherOffset, cipherLength);

        byte[] plaintext;
        try {
            plaintext = enc.decryptBlocks(ciphertext, firstBlock, fileId);
        } catch (GeneralSecurityException e) {
            throw new IOException("corrupt block in file", e);
        }

        int want = (int) length;
        int available = plaintext.length - skip;
        if (available <= 0) {
            return -1;
        }
        int n = Math.min(want, available);
        dst.put(plaintext, skip, n);
        return n;
    }

    /**
     * Writes {@code src.remaining()} plaintext bytes at {@code plainOffset},
     * performing read-modify-write for partial blocks.
     *
     * @return number of bytes written.
     */
    public int write(ByteBuffer src, long plainOffset) throws IOException {
        int length = src.remaining();
        if (length == 0) {
            return 0;
        }

        // Zero-pad any hole up to a block boundary so that the ciphertext file
        // always consists of whole blocks except possibly the last one.
        long oldSize = plainSize();
        if (plainOffset > oldSize) {
            long blockStart = (plainOffset / enc.plainBS) * enc.plainBS;
            if (blockStart > oldSize) {
                writeZeros(oldSize, blockStart - oldSize);
            }
        }

        byte[] fileId = ensureFileId();

        long firstBlock = plainOffset / enc.plainBS;
        int skip = (int) (plainOffset % enc.plainBS);
        long lastBlock = (plainOffset + length - 1) / enc.plainBS;

        ByteArrayOutputStream out = new ByteArrayOutputStream((int) ((lastBlock - firstBlock + 1) * enc.cipherBS));

        for (long b = firstBlock; b <= lastBlock; b++) {
            long blockStart = b * enc.plainBS;
            long lo = Math.max(plainOffset, blockStart);
            long hi = Math.min(plainOffset + length, blockStart + enc.plainBS);
            int segLen = (int) (hi - lo);
            int segSkip = (int) (lo - blockStart);

            byte[] seg = new byte[segLen];
            src.get(seg);

            byte[] plainBlock;
            boolean partial = segSkip > 0 || segLen < enc.plainBS;
            if (partial) {
                byte[] old = readPlainBlock(b);
                plainBlock = merge(old, seg, segSkip);
            } else {
                plainBlock = seg;
            }

            byte[] cipherBlock = enc.encryptBlock(plainBlock, b, fileId);
            out.write(cipherBlock, 0, cipherBlock.length);
        }

        long cipherOffset = enc.blockNoToCipherOff(firstBlock);
        writeCipherRange(cipherOffset, out.toByteArray());
        return length;
    }

    /** Truncates the file to {@code newPlainSize} plaintext bytes. */
    public void truncate(long newPlainSize) throws IOException {
        long oldSize = plainSize();
        if (newPlainSize == oldSize) {
            return;
        }
        if (newPlainSize == 0) {
            channel.truncate(0);
            fileId = null;
            fileIdLoaded = true;
            return;
        }
        byte[] fileId = ensureFileId();

        if (newPlainSize > oldSize) {
            byte[] zeros = new byte[(int) enc.plainBS];
            long remaining = newPlainSize - oldSize;
            long pos = oldSize;
            while (remaining > 0) {
                int n = (int) Math.min(zeros.length, remaining);
                ByteBuffer buf = ByteBuffer.wrap(zeros, 0, n);
                write(buf, pos);
                pos += n;
                remaining -= n;
            }
        } else {
            long blockNo = (newPlainSize - 1) / enc.plainBS;
            long blockStart = blockNo * enc.plainBS;
            int keep = (int) (newPlainSize - blockStart);
            byte[] blockPlain = readPlainBlock(blockNo);
            byte[] truncated = Arrays.copyOf(blockPlain, keep);
            byte[] cipherBlock = enc.encryptBlock(truncated, blockNo, fileId);
            writeCipherRange(enc.blockNoToCipherOff(blockNo), cipherBlock);
            channel.truncate(enc.plainSizeToCipherSize(newPlainSize));
        }
    }

    private byte[] ensureFileId() throws IOException {
        if (!fileIdLoaded) {
            long size = channel.size();
            if (size == 0) {
                FileHeader h = FileHeader.random();
                writeCipherRange(0, h.pack());
                fileId = h.id();
            } else {
                byte[] hdr = readCipherRange(0, Constants.HEADER_LEN);
                if (hdr.length < Constants.HEADER_LEN) {
                    throw new IOException("corrupt file header");
                }
                fileId = FileHeader.parse(hdr).id();
            }
            fileIdLoaded = true;
        }
        if (fileId == null) {
            throw new IOException("could not determine file id");
        }
        return fileId;
    }

    /** Reads and decrypts a whole plaintext block. Empty beyond EOF (gocryptfs semantics). */
    private byte[] readPlainBlock(long blockNo) throws IOException {
        byte[] fileId = fileId();
        long cipherOffset = enc.blockNoToCipherOff(blockNo);
        long cipherSize = channel.size();
        if (cipherOffset >= cipherSize) {
            return new byte[0];
        }
        int len = (int) Math.min(enc.cipherBS, cipherSize - cipherOffset);
        byte[] cBlock = readCipherRange(cipherOffset, len);
        try {
            return enc.decryptBlock(cBlock, blockNo, fileId);
        } catch (GeneralSecurityException e) {
            throw new IOException("corrupt block in file", e);
        }
    }

    /** Zero-fills the plaintext range {@code [offset, offset+length)}. */
    private void writeZeros(long offset, long length) throws IOException {
        byte[] zeros = new byte[(int) enc.plainBS];
        long remaining = length;
        long pos = offset;
        while (remaining > 0) {
            int n = (int) Math.min(zeros.length, remaining);
            ByteBuffer buf = ByteBuffer.wrap(zeros, 0, n);
            write(buf, pos);
            pos += n;
            remaining -= n;
        }
    }

    private static byte[] merge(byte[] oldData, byte[] newData, int offset) {
        int outLen = Math.max(oldData.length, offset + newData.length);
        byte[] out = new byte[outLen];
        System.arraycopy(oldData, 0, out, 0, oldData.length);
        System.arraycopy(newData, 0, out, offset, newData.length);
        return out;
    }

    private byte[] readCipherRange(long offset, int length) throws IOException {
        byte[] buf = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(buf);
        long pos = offset;
        while (bb.hasRemaining()) {
            int n = channel.read(bb, pos);
            if (n < 0) {
                break;
            }
            pos += n;
        }
        if (bb.position() == 0) {
            return new byte[0];
        }
        return Arrays.copyOf(buf, bb.position());
    }

    private void writeCipherRange(long offset, byte[] data) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(data);
        long pos = offset;
        while (bb.hasRemaining()) {
            pos += channel.write(bb, pos);
        }
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
