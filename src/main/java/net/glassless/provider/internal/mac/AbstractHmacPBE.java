package net.glassless.provider.internal.mac;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for PBE-based HMAC implementations.
 * Derives the HMAC key from a password using PBKDF2.
 */
public abstract class AbstractHmacPBE extends MacSpi {

    private final String digestName;
    private final String kdfDigestName; // Digest used for PBKDF2
    private final int macLength;
    private final int derivedKeyLength;

    private int evpMac;
    private int evpMacCtx;
    private byte[] derivedKey;
    private boolean initialized = false;

    protected AbstractHmacPBE(String digestName, String kdfDigestName, int macLength, int derivedKeyLength) {
        this.digestName = digestName;
        this.kdfDigestName = kdfDigestName;
        this.macLength = macLength;
        this.derivedKeyLength = derivedKeyLength;
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

        // Extract password from key
        char[] password;
        if (key instanceof PBEKey) {
            password = ((PBEKey) key).getPassword();
        } else if (key instanceof SecretKey) {
            byte[] keyBytes = key.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("Key encoding not available");
            }
            password = new String(keyBytes, java.nio.charset.StandardCharsets.UTF_8).toCharArray();
        } else {
            throw new InvalidKeyException("Key must be a PBEKey or SecretKey");
        }

        // Extract salt and iteration count from params
        if (!(params instanceof PBEParameterSpec)) {
            throw new InvalidAlgorithmParameterException("PBEParameterSpec required");
        }

        PBEParameterSpec pbeParams = (PBEParameterSpec) params;
        byte[] salt = pbeParams.getSalt();
        int iterationCount = pbeParams.getIterationCount();

        try {
            // Derive the key using PBKDF2
            derivedKey = OpenSSLCrypto.PKCS5_PBKDF2_HMAC(password, salt, iterationCount, kdfDigestName, derivedKeyLength);

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
            int keyPtr = OpenSSLCrypto.malloc(derivedKey.length);
            OpenSSLCrypto.memory().write(keyPtr, derivedKey);

            // Initialize the MAC
            int result = OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keyPtr, derivedKey.length, paramsPtr);
            if (result != 1) {
                throw new InvalidKeyException("Failed to initialize HMAC");
            }

            initialized = true;

        } catch (InvalidKeyException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error initializing PBE HMAC", e);
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
            engineReset();
        }
    }

    @Override
    protected void engineReset() {
        if (evpMacCtx != 0 && derivedKey != null) {
            try {
                // Re-initialize the context for reuse
                int paramsPtr = OpenSSLCrypto.createDigestParams(digestName);
                int keyPtr = OpenSSLCrypto.malloc(derivedKey.length);
                OpenSSLCrypto.memory().write(keyPtr, derivedKey);

                OpenSSLCrypto.EVP_MAC_init(evpMacCtx, keyPtr, derivedKey.length, paramsPtr);
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
