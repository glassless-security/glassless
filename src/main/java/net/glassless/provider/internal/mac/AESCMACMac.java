package net.glassless.provider.internal.mac;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * AES-CMAC implementation using OpenSSL.
 * CMAC (Cipher-based Message Authentication Code) as defined in NIST SP 800-38B.
 */
public class AESCMACMac extends AbstractMac {

    public AESCMACMac() {
        super("CMAC", 16);  // AES-CMAC produces a 128-bit (16 byte) tag
    }

    @Override
    protected MemorySegment createParams(Arena arena) {
        // CMAC requires a cipher parameter
        MemorySegment params = arena.allocate(OpenSSLCrypto.OSSL_PARAM_SIZE * 2);

        // Cipher parameter
        byte[] keyBytes = "cipher".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        MemorySegment keySegment = arena.allocate(keyBytes.length + 1);
        keySegment.asByteBuffer().put(keyBytes).put((byte) 0);

        byte[] valueBytes = "AES-128-CBC".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        MemorySegment valueSegment = arena.allocate(valueBytes.length + 1);
        valueSegment.asByteBuffer().put(valueBytes).put((byte) 0);

        params.set(ValueLayout.ADDRESS, 0, keySegment);
        params.set(ValueLayout.JAVA_INT, 8, OpenSSLCrypto.OSSL_PARAM_UTF8_STRING);
        params.set(ValueLayout.ADDRESS, 16, valueSegment);
        params.set(ValueLayout.JAVA_LONG, 24, valueBytes.length);
        params.set(ValueLayout.JAVA_LONG, 32, 0L);

        // End marker
        params.set(ValueLayout.ADDRESS, OpenSSLCrypto.OSSL_PARAM_SIZE, MemorySegment.NULL);

        return params;
    }
}
