package net.glassless.provider.internal.mac;

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

    private int evpMac;
    private int evpMacCtx;
    private byte[] keyBytes;
    private boolean initialized = false;

    protected AbstractMac(String macAlgorithm, int macLength) {
        this.macAlgorithm = macAlgorithm;
        this.macLength = macLength;
    }

    @Override
    protected int engineGetMacLength() {
        return macLength;
    }

    /**
     * Creates the OSSL_PARAM array for MAC initialization.
     * Subclasses can override to add algorithm-specific parameters.
     * Returns a wasm pointer to the OSSL_PARAM array.
     */
    protected int createParams() {
        // Default: no additional parameters (end marker only)
        int paramSize = OpenSSLCrypto.glasslessSizeofOSSLPARAM();
        int params = OpenSSLCrypto.malloc(paramSize);
        OpenSSLCrypto.memory().writeI32(params, 0);
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
            evpMac = OpenSSLCrypto.EVP_MAC_fetch(0, macAlgorithm, 0);
            if (evpMac == 0) {
                throw new ProviderException("Failed to fetch MAC: " + macAlgorithm);
            }

            // Create MAC context
            evpMacCtx = OpenSSLCrypto.EVP_MAC_CTX_new(evpMac);
            if (evpMacCtx == 0) {
                throw new ProviderException("Failed to create MAC context");
            }

            // Create params for the MAC
            int paramsPtr = createParams();

            // Allocate key segment
            int keyPtr = OpenSSLCrypto.malloc(keyBytes.length);
            OpenSSLCrypto.memory().write(keyPtr, keyBytes);

            // Initialize the MAC
            int result = OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keyPtr, keyBytes.length, paramsPtr);
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

        int inputPtr = OpenSSLCrypto.malloc(len);
        try {
            OpenSSLCrypto.memory().write(inputPtr, input, offset, len);

            int result = OpenSSLCrypto.EVP_MAC_update(evpMacCtx, inputPtr, len);
            if (result != 1) {
                throw new ProviderException("MAC update failed");
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error updating MAC", e);
        } finally {
            OpenSSLCrypto.free(inputPtr);
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        if (!initialized) {
            throw new IllegalStateException("MAC not initialized");
        }

        int outPtr = OpenSSLCrypto.malloc(macLength);
        int outLenPtr = OpenSSLCrypto.malloc(4);
        try {
            int result = OpenSSLCrypto.EVP_MAC_final(evpMacCtx, outPtr, outLenPtr, macLength);
            if (result != 1) {
                throw new ProviderException("MAC final failed");
            }

            int outLen = OpenSSLCrypto.memory().readInt(outLenPtr);
            byte[] mac = OpenSSLCrypto.memory().readBytes(outPtr, outLen);

            return mac;

        } catch (Throwable e) {
            throw new ProviderException("Error finalizing MAC", e);
        } finally {
            OpenSSLCrypto.free(outPtr);
            OpenSSLCrypto.free(outLenPtr);
            // Reset for potential reuse
            engineReset();
        }
    }

    @Override
    protected void engineReset() {
        if (evpMacCtx != 0 && keyBytes != null) {
            try {
                // Re-initialize the context for reuse
                int paramsPtr = createParams();
                int keyPtr = OpenSSLCrypto.malloc(keyBytes.length);
                OpenSSLCrypto.memory().write(keyPtr, keyBytes);

                OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keyPtr, keyBytes.length, paramsPtr);
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
