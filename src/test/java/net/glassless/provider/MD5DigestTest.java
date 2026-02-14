package net.glassless.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.MessageDigest;
import java.security.Security;
import java.util.HexFormat;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class MD5DigestTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new GlaSSLessProvider());
    }

    @Nested
    @DisplayName("MD5 Basic Tests")
    class BasicTests {

        @Test
        @DisplayName("MD5 digest length is 16 bytes")
        void testDigestLength() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5", "GlaSSLess");
            assertEquals(16, md.getDigestLength());
        }

        @Test
        @DisplayName("MD5 of empty string")
        void testEmptyString() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5", "GlaSSLess");
            byte[] digest = md.digest(new byte[0]);

            // MD5("") = d41d8cd98f00b204e9800998ecf8427e
            String expected = "d41d8cd98f00b204e9800998ecf8427e";
            assertEquals(expected, HexFormat.of().formatHex(digest));
        }

        @Test
        @DisplayName("MD5 of 'hello'")
        void testHello() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5", "GlaSSLess");
            byte[] digest = md.digest("hello".getBytes());

            // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
            String expected = "5d41402abc4b2a76b9719d911017c592";
            assertEquals(expected, HexFormat.of().formatHex(digest));
        }

        @Test
        @DisplayName("MD5 of 'The quick brown fox jumps over the lazy dog'")
        void testQuickBrownFox() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5", "GlaSSLess");
            byte[] digest = md.digest("The quick brown fox jumps over the lazy dog".getBytes());

            // MD5("The quick brown fox jumps over the lazy dog") = 9e107d9d372bb6826bd81d3542a419d6
            String expected = "9e107d9d372bb6826bd81d3542a419d6";
            assertEquals(expected, HexFormat.of().formatHex(digest));
        }

        @Test
        @DisplayName("MD5 incremental update")
        void testIncrementalUpdate() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5", "GlaSSLess");
            md.update("hello".getBytes());
            md.update(" ".getBytes());
            md.update("world".getBytes());
            byte[] digest = md.digest();

            // MD5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
            String expected = "5eb63bbbe01eeed093cb22bb8f5acdc3";
            assertEquals(expected, HexFormat.of().formatHex(digest));
        }

        @Test
        @DisplayName("MD5 reset")
        void testReset() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5", "GlaSSLess");
            md.update("some data".getBytes());
            md.reset();
            byte[] digest = md.digest("hello".getBytes());

            // Should be MD5("hello"), not MD5("some datahello")
            String expected = "5d41402abc4b2a76b9719d911017c592";
            assertEquals(expected, HexFormat.of().formatHex(digest));
        }

        @Test
        @DisplayName("MD5 multiple digests")
        void testMultipleDigests() throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5", "GlaSSLess");

            byte[] digest1 = md.digest("hello".getBytes());
            byte[] digest2 = md.digest("world".getBytes());

            // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
            // MD5("world") = 7d793037a0760186574b0282f2f435e7
            assertEquals("5d41402abc4b2a76b9719d911017c592", HexFormat.of().formatHex(digest1));
            assertEquals("7d793037a0760186574b0282f2f435e7", HexFormat.of().formatHex(digest2));
        }
    }

    @Nested
    @DisplayName("Cross-provider Compatibility Tests")
    class CrossProviderTests {

        @Test
        @DisplayName("GlaSSLess MD5 matches default provider")
        void testCrossProvider() throws Exception {
            byte[] data = "Cross-provider MD5 test data".getBytes();

            MessageDigest glasslessMd = MessageDigest.getInstance("MD5", "GlaSSLess");
            byte[] glasslessDigest = glasslessMd.digest(data);

            MessageDigest defaultMd = MessageDigest.getInstance("MD5");
            byte[] defaultDigest = defaultMd.digest(data);

            assertArrayEquals(defaultDigest, glasslessDigest,
                "GlaSSLess MD5 should match default provider");
        }

        @Test
        @DisplayName("MD5 via OID alias")
        void testOidAlias() throws Exception {
            // MD5 OID: 1.2.840.113549.2.5
            MessageDigest md = MessageDigest.getInstance("1.2.840.113549.2.5", "GlaSSLess");
            byte[] digest = md.digest("hello".getBytes());

            assertEquals("5d41402abc4b2a76b9719d911017c592", HexFormat.of().formatHex(digest));
        }
    }
}
