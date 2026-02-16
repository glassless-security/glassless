package net.glassless.provider.internal.cipher;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for RSA ciphers using OpenSSL EVP_PKEY API.
 */
abstract class AbstractRSACipher extends CipherSpi {

    private final RSAPadding padding;
    private final String oaepDigest; // For OAEP padding, null otherwise

    private int evpPkey;
    private int evpPkeyCtx;
    private int opmode;
    private int keySize; // in bytes

    protected AbstractRSACipher(RSAPadding padding, String oaepDigest) {
        this.padding = padding;
        this.oaepDigest = oaepDigest;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        // RSA typically uses ECB mode (single block)
        if (!mode.equalsIgnoreCase("ECB") && !mode.equalsIgnoreCase("NONE")) {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String paddingStr) throws NoSuchPaddingException {
        // Padding is fixed at construction time
        String normalizedPadding = paddingStr.toUpperCase().replace("PADDING", "PADDING");
        if (!this.padding.name().equalsIgnoreCase(normalizedPadding.replace("PADDING", "PADDING"))) {
            throw new NoSuchPaddingException("Unsupported padding: " + paddingStr);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        // RSA block size is the key size
        return keySize > 0 ? keySize : 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return keySize > 0 ? keySize : 256; // Default to 2048-bit key size
    }

    @Override
    protected byte[] engineGetIV() {
        return null; // RSA doesn't use IV
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;

        if (!(key instanceof RSAKey)) {
            throw new InvalidKeyException("Key must be an RSA key");
        }

        RSAKey rsaKey = (RSAKey) key;
        this.keySize = (rsaKey.getModulus().bitLength() + 7) / 8;

        try {
            // Get the encoded key bytes
            byte[] keyBytes = key.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("Key encoding not available");
            }

            // Load the key using loadPrivateKey or loadPublicKey
            if (key instanceof PrivateKey) {
                evpPkey = OpenSSLCrypto.loadPrivateKey(OpenSSLCrypto.EVP_PKEY_RSA, keyBytes);
            } else if (key instanceof PublicKey) {
                evpPkey = OpenSSLCrypto.loadPublicKey(keyBytes);
            } else {
                throw new InvalidKeyException("Key must be a PublicKey or PrivateKey");
            }

            if (evpPkey == 0) {
                throw new InvalidKeyException("Failed to load RSA key");
            }

            // Create EVP_PKEY_CTX
            evpPkeyCtx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(0, evpPkey, 0);
            if (evpPkeyCtx == 0) {
                throw new InvalidKeyException("Failed to create EVP_PKEY_CTX");
            }

            // Initialize for encryption or decryption
            int result;
            if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
                result = OpenSSLCrypto.EVP_PKEY_encrypt_init(evpPkeyCtx);
            } else {
                result = OpenSSLCrypto.EVP_PKEY_decrypt_init(evpPkeyCtx);
            }

            if (result <= 0) {
                throw new InvalidKeyException("Failed to initialize RSA operation");
            }

            // Set padding
            result = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_padding(evpPkeyCtx, padding.getOpenSSLPadding());
            if (result <= 0) {
                throw new InvalidKeyException("Failed to set RSA padding");
            }

            // For OAEP, set the digest algorithms
            if (padding == RSAPadding.OAEPPADDING && oaepDigest != null) {
                int digestHandle = OpenSSLCrypto.getDigestHandle(oaepDigest);
                if (digestHandle == 0) {
                    throw new InvalidKeyException("Unknown OAEP digest: " + oaepDigest);
                }

                result = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_oaep_md(evpPkeyCtx, digestHandle);
                if (result <= 0) {
                    throw new InvalidKeyException("Failed to set OAEP digest");
                }

                result = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_mgf1_md(evpPkeyCtx, digestHandle);
                if (result <= 0) {
                    throw new InvalidKeyException("Failed to set MGF1 digest");
                }
            }

        } catch (InvalidKeyException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error initializing RSA cipher", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        // RSA is a single-block cipher, so we buffer the input until doFinal
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input == null || inputLen == 0) {
            throw new IllegalBlockSizeException("No input data");
        }

        int inputPtr = 0;
        int outLenPtr = 0;
        int outputPtr = 0;
        try {
            // Allocate input buffer
            inputPtr = OpenSSLCrypto.malloc(inputLen);
            OpenSSLCrypto.memory().write(inputPtr, input, inputOffset, inputLen);

            // Allocate output length segment (wasm32: use int, 4 bytes)
            outLenPtr = OpenSSLCrypto.malloc(4);

            int result;

            if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
                // First call to get output size
                result = OpenSSLCrypto.EVP_PKEY_encrypt(evpPkeyCtx, 0, outLenPtr, inputPtr, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA encryption failed (size query)");
                }

                int outLen = OpenSSLCrypto.memory().readInt(outLenPtr);
                outputPtr = OpenSSLCrypto.malloc(outLen);

                // Actual encryption
                result = OpenSSLCrypto.EVP_PKEY_encrypt(evpPkeyCtx, outputPtr, outLenPtr, inputPtr, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA encryption failed");
                }

                outLen = OpenSSLCrypto.memory().readInt(outLenPtr);
                byte[] output = OpenSSLCrypto.memory().readBytes(outputPtr, outLen);
                return output;

            } else {
                // First call to get output size
                result = OpenSSLCrypto.EVP_PKEY_decrypt(evpPkeyCtx, 0, outLenPtr, inputPtr, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA decryption failed (size query)");
                }

                int outLen = OpenSSLCrypto.memory().readInt(outLenPtr);
                outputPtr = OpenSSLCrypto.malloc(outLen);

                // Actual decryption
                result = OpenSSLCrypto.EVP_PKEY_decrypt(evpPkeyCtx, outputPtr, outLenPtr, inputPtr, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA decryption failed");
                }

                outLen = OpenSSLCrypto.memory().readInt(outLenPtr);
                byte[] output = OpenSSLCrypto.memory().readBytes(outputPtr, outLen);
                return output;
            }

        } catch (BadPaddingException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error in RSA operation", e);
        } finally {
            OpenSSLCrypto.free(inputPtr);
            OpenSSLCrypto.free(outLenPtr);
            OpenSSLCrypto.free(outputPtr);
            reset();
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer too short");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    private void reset() {
        if (evpPkeyCtx != 0) {
            try {
                OpenSSLCrypto.EVP_PKEY_CTX_free(evpPkeyCtx);
            } catch (Throwable e) {
                // Ignore
            }
            evpPkeyCtx = 0;
        }
        if (evpPkey != 0) {
            try {
                OpenSSLCrypto.EVP_PKEY_free(evpPkey);
            } catch (Throwable e) {
                // Ignore
            }
            evpPkey = 0;
        }
    }
}
