package net.glassless.provider.internal.mac;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for HMAC implementations using OpenSSL EVP_MAC API.
 */
public abstract class AbstractHmac extends MacSpi {

    private final String digestName;
    private final int macLength;
    private final Arena arena;

    private MemorySegment evpMac;
    private MemorySegment evpMacCtx;
    private byte[] keyBytes;
    private boolean initialized = false;

    protected AbstractHmac(String digestName, int macLength) {
        this.digestName = digestName;
        this.macLength = macLength;
        this.arena = Arena.ofShared();
    }

    @Override
    protected int engineGetMacLength() {
        return macLength;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey");
        }

        keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("Key encoding not available");
        }

        try {
            // Fetch the HMAC implementation
            evpMac = OpenSSLCrypto.EVP_MAC_fetch(MemorySegment.NULL, "HMAC", MemorySegment.NULL, arena);
            if (evpMac.equals(MemorySegment.NULL)) {
                throw new ProviderException("Failed to fetch HMAC");
            }

            // Create MAC context
            evpMacCtx = OpenSSLCrypto.EVP_MAC_CTX_new(evpMac);
            if (evpMacCtx.equals(MemorySegment.NULL)) {
                throw new ProviderException("Failed to create MAC context");
            }

            // Create params for the digest
            MemorySegment paramsSegment = OpenSSLCrypto.createDigestParams(digestName, arena);

            // Allocate key segment
            MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
            keySegment.asByteBuffer().put(keyBytes);

            // Initialize the MAC
            int result = OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keySegment, keyBytes.length, paramsSegment);
            if (result != 1) {
                throw new InvalidKeyException("Failed to initialize HMAC");
            }

            initialized = true;

        } catch (InvalidKeyException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error initializing HMAC", e);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (!initialized) {
            throw new IllegalStateException("MAC not initialized");
        }

        if (len == 0) {
            return;
        }

        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment inputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, len);
            inputSegment.asByteBuffer().put(input, offset, len);

            int result = OpenSSLCrypto.EVP_MAC_update(evpMacCtx, inputSegment, len);
            if (result != 1) {
                throw new ProviderException("HMAC update failed");
            }
        } catch (Throwable e) {
            throw new ProviderException("Error updating HMAC", e);
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        if (!initialized) {
            throw new IllegalStateException("MAC not initialized");
        }

        try (Arena confinedArena = Arena.ofConfined()) {
            // Allocate output buffer
            MemorySegment outSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, macLength);
            MemorySegment outLenSegment = confinedArena.allocate(ValueLayout.JAVA_LONG);

            int result = OpenSSLCrypto.EVP_MAC_final(evpMacCtx, outSegment, outLenSegment, macLength);
            if (result != 1) {
                throw new ProviderException("HMAC final failed");
            }

            long outLen = outLenSegment.get(ValueLayout.JAVA_LONG, 0);
            byte[] mac = new byte[(int) outLen];
            outSegment.asByteBuffer().get(mac);

            return mac;

        } catch (Throwable e) {
            throw new ProviderException("Error finalizing HMAC", e);
        } finally {
            // Reset for potential reuse
            engineReset();
        }
    }

    @Override
    protected void engineReset() {
        if (evpMacCtx != null && keyBytes != null) {
            try {
                // Re-initialize the context for reuse
                MemorySegment paramsSegment = OpenSSLCrypto.createDigestParams(digestName, arena);
                MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
                keySegment.asByteBuffer().put(keyBytes);

                OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keySegment, keyBytes.length, paramsSegment);
            } catch (Throwable e) {
                // Ignore reset errors
            }
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("HMAC clone not supported");
    }
}
