package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class GocryptFsProviderTest {

    @TempDir
    Path tmp;

    @Test
    void nioTraversal() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/a");
            fs.createFile("/a/one.txt");
            fs.write("/a/one.txt", 0, "one".getBytes(StandardCharsets.UTF_8));
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            Path root = nio.getPath("/");
            assertEquals("/", root.toString());

            // Directory traversal
            Set<String> names = new HashSet<>();
            try (DirectoryStream<Path> ds = provider.newDirectoryStream(root, null)) {
                for (Path p : ds) {
                    names.add(p.getFileName().toString());
                }
            }
            assertEquals(Set.of("a"), names);

            Path one = nio.getPath("/a/one.txt");
            assertArrayEquals("one".getBytes(StandardCharsets.UTF_8),
                    Files.readAllBytes(one));
        }
    }

    @Test
    void nioReadWriteViaFilesApi() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/data");
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            Path file = nio.getPath("/data/numbers.bin");
            byte[] data = new byte[12345];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) (i & 0xFF);
            }
            Files.write(file, data);
            assertArrayEquals(data, Files.readAllBytes(file));
            assertEquals(data.length, Files.size(file));

            Path sub = nio.getPath("/data/sub");
            Files.createDirectory(sub);
            Files.write(sub.resolve("x.txt"), "x".getBytes(StandardCharsets.UTF_8));
            assertEquals("x", Files.readString(sub.resolve("x.txt")));

            Files.delete(file);
            assertFalse(Files.exists(file));
        }
    }
}
