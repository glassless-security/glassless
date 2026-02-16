package net.glassless.provider.internal.cipher;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for PBE (Password-Based Encryption) ciphers.
 * Uses PKCS5 PBKDF2 HMAC for key derivation and delegates to an underlying cipher.
 */
abstract class AbstractPBECipher extends CipherSpi {

    private final String opensslCipherName;
    private final int keySize;
    private final CipherMode mode;
    private final String prf; // Pseudo-Random Function (hash algorithm for PBKDF2)

    private int evpCipherCtx;
    private int evpCipher;
    private int opmode;
    private byte[] iv;
    private byte[] derivedKey;

    private static final int DEFAULT_ITERATION_COUNT = 10000;
    private static final int IV_LENGTH = 16; // AES block size

    /**
     * Creates a new PBE cipher.
     *
     * @param opensslCipherName the OpenSSL cipher name (e.g., "aes-128-cbc")
     * @param keySize the key size in bytes
     * @param mode the cipher mode
     * @param prf the pseudo-random function for PBKDF2 (e.g., "SHA256", "SHA1")
     */
    protected AbstractPBECipher(String opensslCipherName, int keySize, CipherMode mode, String prf) {
        this.opensslCipherName = opensslCipherName;
        this.keySize = keySize;
        this.mode = mode;
        this.prf = prf;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!this.mode.name().equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        // PBE ciphers typically use PKCS5Padding
        if (!padding.equalsIgnoreCase("PKCS5Padding") && !padding.equalsIgnoreCase("PKCS7Padding")) {
            throw new NoSuchPaddingException("Unsupported padding: " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 16; // AES block size
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // Conservative estimate including padding
        return inputLen + engineGetBlockSize();
    }

    @Override
    protected byte[] engineGetIV() {
        return this.iv == null ? null : this.iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new InvalidKeyException("PBE cipher requires PBEParameterSpec");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;

        // Extract password from key
        char[] password;
        if (key instanceof PBEKey) {
            password = ((PBEKey) key).getPassword();
        } else if (key instanceof SecretKey) {
            // Assume the key bytes are the password encoded as UTF-8
            byte[] keyBytes = key.getEncoded();
            password = new String(keyBytes, java.nio.charset.StandardCharsets.UTF_8).toCharArray();
        } else {
            throw new InvalidKeyException("Key must be a PBEKey or SecretKey");
        }

        // Extract salt and iteration count from params
        byte[] salt;
        int iterationCount;
        AlgorithmParameterSpec ivSpec = null;

        if (params instanceof PBEParameterSpec) {
            PBEParameterSpec pbeParams = (PBEParameterSpec) params;
            salt = pbeParams.getSalt();
            iterationCount = pbeParams.getIterationCount();
            ivSpec = pbeParams.getParameterSpec();
        } else {
            throw new InvalidAlgorithmParameterException("PBEParameterSpec required");
        }

        // Extract IV if provided
        if (ivSpec instanceof IvParameterSpec) {
            this.iv = ((IvParameterSpec) ivSpec).getIV();
        } else if (mode != CipherMode.ECB) {
            // Generate random IV if not provided
            this.iv = new byte[IV_LENGTH];
            if (random == null) {
                random = new SecureRandom();
            }
            random.nextBytes(this.iv);
        }

        int keyPtr = 0;
        int ivPtr = 0;
        try {
            // Derive the key using PBKDF2
            derivedKey = OpenSSLCrypto.PKCS5_PBKDF2_HMAC(password, salt, iterationCount, prf, keySize);

            // Initialize the underlying cipher
            evpCipher = OpenSSLCrypto.EVP_get_cipherbyname(opensslCipherName);
            if (evpCipher == 0) {
                throw new ProviderException("Failed to get cipher: " + opensslCipherName);
            }

            evpCipherCtx = OpenSSLCrypto.EVP_CIPHER_CTX_new();
            if (evpCipherCtx == 0) {
                throw new ProviderException("Failed to create EVP_CIPHER_CTX");
            }

            keyPtr = OpenSSLCrypto.malloc(derivedKey.length);
            OpenSSLCrypto.memory().write(keyPtr, derivedKey);

            if (iv != null) {
                ivPtr = OpenSSLCrypto.malloc(iv.length);
                OpenSSLCrypto.memory().write(ivPtr, iv);
            }

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptInit_ex(evpCipherCtx, evpCipher, 0, keyPtr, ivPtr);
            } else {
                result = OpenSSLCrypto.EVP_DecryptInit_ex(evpCipherCtx, evpCipher, 0, keyPtr, ivPtr);
            }

            if (result != 1) {
                throw new InvalidKeyException("Cipher initialization failed");
            }

        } catch (Throwable e) {
            throw new ProviderException("Error initializing PBE cipher", e);
        } finally {
            OpenSSLCrypto.free(keyPtr);
            OpenSSLCrypto.free(ivPtr);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("engineInit with AlgorithmParameters not supported");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (inputLen == 0) {
            return null;
        }
        byte[] output = new byte[engineGetOutputSize(inputLen)];
        try {
            int outputLen = engineUpdate(input, inputOffset, inputLen, output, 0);
            if (outputLen == 0) {
                return null;
            }
            byte[] result = new byte[outputLen];
            System.arraycopy(output, 0, result, 0, outputLen);
            return result;
        } catch (ShortBufferException e) {
            throw new ProviderException(e);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        int inputPtr = 0;
        int outputPtr = 0;
        int outLenPtr = 0;
        try {
            inputPtr = OpenSSLCrypto.malloc(inputLen);
            OpenSSLCrypto.memory().write(inputPtr, input, inputOffset, inputLen);

            outputPtr = OpenSSLCrypto.malloc(output.length - outputOffset);
            outLenPtr = OpenSSLCrypto.malloc(4);

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptUpdate(evpCipherCtx, outputPtr, outLenPtr, inputPtr, inputLen);
            } else {
                result = OpenSSLCrypto.EVP_DecryptUpdate(evpCipherCtx, outputPtr, outLenPtr, inputPtr, inputLen);
            }

            if (result != 1) {
                throw new ProviderException("Cipher update failed");
            }

            int written = OpenSSLCrypto.memory().readInt(outLenPtr);
            byte[] tmp = OpenSSLCrypto.memory().readBytes(outputPtr, written);
            System.arraycopy(tmp, 0, output, outputOffset, written);
            return written;
        } catch (Throwable e) {
            throw new ProviderException("Error updating cipher", e);
        } finally {
            OpenSSLCrypto.free(inputPtr);
            OpenSSLCrypto.free(outputPtr);
            OpenSSLCrypto.free(outLenPtr);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        int currentUpdateOutputPtr = 0;
        int currentOutLenPtr = 0;
        int inputPtr = 0;
        int finalOutputPtr = 0;
        int finalOutLenPtr = 0;
        try {
            // Step 1: Process any remaining input
            int currentUpdateOutputLen = 0;

            if (input != null && inputLen > 0) {
                int conservativeOutputSize = inputLen + engineGetBlockSize();
                currentUpdateOutputPtr = OpenSSLCrypto.malloc(conservativeOutputSize);
                currentOutLenPtr = OpenSSLCrypto.malloc(4);

                inputPtr = OpenSSLCrypto.malloc(inputLen);
                OpenSSLCrypto.memory().write(inputPtr, input, inputOffset, inputLen);

                int result;
                if (opmode == Cipher.ENCRYPT_MODE) {
                    result = OpenSSLCrypto.EVP_EncryptUpdate(evpCipherCtx, currentUpdateOutputPtr, currentOutLenPtr, inputPtr, inputLen);
                } else {
                    result = OpenSSLCrypto.EVP_DecryptUpdate(evpCipherCtx, currentUpdateOutputPtr, currentOutLenPtr, inputPtr, inputLen);
                }
                if (result != 1) {
                    throw new ProviderException("Cipher update failed in engineDoFinal");
                }
                currentUpdateOutputLen = OpenSSLCrypto.memory().readInt(currentOutLenPtr);
            }

            // Step 2: Finalize
            int finalOutputSegmentSize = engineGetOutputSize(0);
            finalOutputPtr = OpenSSLCrypto.malloc(finalOutputSegmentSize);
            finalOutLenPtr = OpenSSLCrypto.malloc(4);

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptFinal_ex(evpCipherCtx, finalOutputPtr, finalOutLenPtr);
            } else {
                result = OpenSSLCrypto.EVP_DecryptFinal_ex(evpCipherCtx, finalOutputPtr, finalOutLenPtr);
            }

            if (result != 1) {
                if (opmode == Cipher.ENCRYPT_MODE) {
                    throw new ProviderException("Cipher finalization failed");
                } else {
                    throw new BadPaddingException("Cipher finalization failed");
                }
            }

            int finalCiphertextLen = OpenSSLCrypto.memory().readInt(finalOutLenPtr);

            // Step 3: Combine outputs
            byte[] outputFromCurrentUpdate = (currentUpdateOutputLen > 0)
                ? OpenSSLCrypto.memory().readBytes(currentUpdateOutputPtr, currentUpdateOutputLen)
                : new byte[0];
            byte[] outputFromFinal = (finalCiphertextLen > 0)
                ? OpenSSLCrypto.memory().readBytes(finalOutputPtr, finalCiphertextLen)
                : new byte[0];

            byte[] finalOutput = new byte[outputFromCurrentUpdate.length + outputFromFinal.length];
            System.arraycopy(outputFromCurrentUpdate, 0, finalOutput, 0, outputFromCurrentUpdate.length);
            System.arraycopy(outputFromFinal, 0, finalOutput, outputFromCurrentUpdate.length, outputFromFinal.length);

            return finalOutput;

        } catch (Throwable e) {
            throw new ProviderException("Error finalizing cipher", e);
        } finally {
            OpenSSLCrypto.free(currentUpdateOutputPtr);
            OpenSSLCrypto.free(currentOutLenPtr);
            OpenSSLCrypto.free(inputPtr);
            OpenSSLCrypto.free(finalOutputPtr);
            OpenSSLCrypto.free(finalOutLenPtr);
            reset();
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] finalOutput = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < finalOutput.length) {
            throw new ShortBufferException("Output buffer too short");
        }
        System.arraycopy(finalOutput, 0, output, outputOffset, finalOutput.length);
        return finalOutput.length;
    }

    private void reset() {
        if (evpCipherCtx != 0) {
            try {
                OpenSSLCrypto.EVP_CIPHER_CTX_free(evpCipherCtx);
            } catch (Throwable e) {
                // Ignore
            }
            evpCipherCtx = 0;
        }
        if (derivedKey != null) {
            java.util.Arrays.fill(derivedKey, (byte) 0);
            derivedKey = null;
        }
    }
}
