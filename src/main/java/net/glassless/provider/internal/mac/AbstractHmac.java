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
 * Abstract base class for HMAC implementations using OpenSSL EVP_MAC API.
 */
public abstract class AbstractHmac extends MacSpi {

    private final String digestName;
    private final int macLength;

    private int evpMac;
    private int evpMacCtx;
    private byte[] keyBytes;
    private boolean initialized = false;

    protected AbstractHmac(String digestName, int macLength) {
        this.digestName = digestName;
        this.macLength = macLength;
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
            evpMac = OpenSSLCrypto.EVP_MAC_fetch(0, "HMAC", 0);
            if (evpMac == 0) {
                throw new ProviderException("Failed to fetch HMAC");
            }

            // Create MAC context
            evpMacCtx = OpenSSLCrypto.EVP_MAC_CTX_new(evpMac);
            if (evpMacCtx == 0) {
                throw new ProviderException("Failed to create MAC context");
            }

            // Create params for the digest
            int paramsPtr = OpenSSLCrypto.createDigestParams(digestName);

            // Allocate key segment
            int keyPtr = OpenSSLCrypto.malloc(keyBytes.length);
            OpenSSLCrypto.memory().write(keyPtr, keyBytes);

            // Initialize the MAC
            int result = OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keyPtr, keyBytes.length, paramsPtr);
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

        int inputPtr = OpenSSLCrypto.malloc(len);
        try {
            OpenSSLCrypto.memory().write(inputPtr, input, offset, len);

            int result = OpenSSLCrypto.EVP_MAC_update(evpMacCtx, inputPtr, len);
            if (result != 1) {
                throw new ProviderException("HMAC update failed");
            }
        } catch (ProviderException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error updating HMAC", e);
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
                throw new ProviderException("HMAC final failed");
            }

            int outLen = OpenSSLCrypto.memory().readInt(outLenPtr);
            byte[] mac = OpenSSLCrypto.memory().readBytes(outPtr, outLen);

            return mac;

        } catch (Throwable e) {
            throw new ProviderException("Error finalizing HMAC", e);
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
                int paramsPtr = OpenSSLCrypto.createDigestParams(digestName);
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
        throw new CloneNotSupportedException("HMAC clone not supported");
    }
}
