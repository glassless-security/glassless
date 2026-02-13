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
 * Abstract base class for MAC implementations using OpenSSL EVP_MAC API.
 * This class supports CMAC, GMAC, KMAC, and other MAC algorithms.
 */
public abstract class AbstractMac extends MacSpi {

    private final String macAlgorithm;
    private final int macLength;
    private final Arena arena;

    private MemorySegment evpMac;
    private MemorySegment evpMacCtx;
    private byte[] keyBytes;
    private boolean initialized = false;

    protected AbstractMac(String macAlgorithm, int macLength) {
        this.macAlgorithm = macAlgorithm;
        this.macLength = macLength;
        this.arena = Arena.ofShared();
    }

    @Override
    protected int engineGetMacLength() {
        return macLength;
    }

    /**
     * Creates the OSSL_PARAM array for MAC initialization.
     * Subclasses can override to add algorithm-specific parameters.
     */
    protected MemorySegment createParams(Arena arena) {
        // Default: no additional parameters (end marker only)
        MemorySegment params = arena.allocate(OpenSSLCrypto.OSSL_PARAM_SIZE);
        params.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
        return params;
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
            // Fetch the MAC implementation
            evpMac = OpenSSLCrypto.EVP_MAC_fetch(MemorySegment.NULL, macAlgorithm, MemorySegment.NULL, arena);
            if (evpMac == null || evpMac.address() == 0) {
                throw new ProviderException("Failed to fetch MAC: " + macAlgorithm);
            }

            // Create MAC context
            evpMacCtx = OpenSSLCrypto.EVP_MAC_CTX_new(evpMac);
            if (evpMacCtx == null || evpMacCtx.address() == 0) {
                throw new ProviderException("Failed to create MAC context");
            }

            // Create params for the MAC
            MemorySegment paramsSegment = createParams(arena);

            // Allocate key segment
            MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
            keySegment.asByteBuffer().put(keyBytes);

            // Initialize the MAC
            int result = OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keySegment, keyBytes.length, paramsSegment);
            if (result != 1) {
                throw new InvalidKeyException("Failed to initialize MAC: " + macAlgorithm);
            }

            initialized = true;

        } catch (InvalidKeyException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error initializing MAC: " + macAlgorithm, e);
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
                throw new ProviderException("MAC update failed");
            }
        } catch (Throwable e) {
            throw new ProviderException("Error updating MAC", e);
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
                throw new ProviderException("MAC final failed");
            }

            long outLen = outLenSegment.get(ValueLayout.JAVA_LONG, 0);
            byte[] mac = new byte[(int) outLen];
            outSegment.asByteBuffer().get(mac);

            return mac;

        } catch (Throwable e) {
            throw new ProviderException("Error finalizing MAC", e);
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
                MemorySegment paramsSegment = createParams(arena);
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
        throw new CloneNotSupportedException("MAC clone not supported");
    }
}
