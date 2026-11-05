package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SharedCipherFileSyncPolicyTest {

    private static final char[] PASSWORD = "pw".toCharArray();

    @TempDir
    Path tmp;

    @Test
    void completedWriteIsVisibleToAnotherInstanceWhileHandleStaysOpen() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        byte[] data = "durable".getBytes(StandardCharsets.UTF_8);
        try (GocryptFs fs = GocryptFs.create(store, PASSWORD)) {
            fs.createFile("/f.txt");
            try (SharedCipherFile open = fs.openCipherFile("/f.txt", true)) {
                fs.write("/f.txt", 0, data);

                // A separate instance has no access to the writer's block cache,
                // so it can only see the data if the write was flushed.
                try (GocryptFs reader = GocryptFs.openReadOnly(store, PASSWORD)) {
                    assertArrayEquals(data, reader.readAll("/f.txt"));
                }
            }
        }
    }

    @Test
    void nonePolicyKeepsWriteBufferedUntilLastHandleCloses() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        byte[] data = "buffered".getBytes(StandardCharsets.UTF_8);
        try (GocryptFs fs = GocryptFs.create(store, PASSWORD)) {
            fs.createFile("/f.txt");
            fs.setSyncPolicy(SyncPolicy.NONE);
            try (SharedCipherFile open = fs.openCipherFile("/f.txt", true)) {
                fs.write("/f.txt", 0, data);

                try (GocryptFs reader = GocryptFs.openReadOnly(store, PASSWORD)) {
                    assertEquals(0, reader.readAll("/f.txt").length,
                            "NONE must not flush before the last handle closes");
                }
            }
            try (GocryptFs reader = GocryptFs.openReadOnly(store, PASSWORD)) {
                assertArrayEquals(data, reader.readAll("/f.txt"));
            }
        }
    }

    @Test
    void alwaysPolicyMakesAnOpenChannelWriteVisibleImmediately() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        byte[] data = "always".getBytes(StandardCharsets.UTF_8);
        try (GocryptFs fs = GocryptFs.create(store, PASSWORD)) {
            fs.createFile("/f.txt");
            try (SharedCipherFile writer = fs.openCipherFile("/f.txt", true,
                    SyncPolicy.ALWAYS);
                 BlockBufferedChannel channel = writer.newChannel(0, true, SyncPolicy.ALWAYS)) {
                channel.write(ByteBuffer.wrap(data));

                try (GocryptFs reader = GocryptFs.openReadOnly(store, PASSWORD)) {
                    assertArrayEquals(data, reader.readAll("/f.txt"));
                }
            }
        }
    }
}
