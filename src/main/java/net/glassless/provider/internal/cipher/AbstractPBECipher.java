package net.glassless.provider.internal.cipher;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
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

    private final Arena arena;
    private final String opensslCipherName;
    private final int keySize;
    private final CipherMode mode;
    private final String prf; // Pseudo-Random Function (hash algorithm for PBKDF2)

    private MemorySegment evpCipherCtx;
    private MemorySegment evpCipher;
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
        this.arena = Arena.ofShared();
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

        try {
            // Derive the key using PBKDF2
            derivedKey = OpenSSLCrypto.PKCS5_PBKDF2_HMAC(password, salt, iterationCount, prf, keySize, arena);

            // Initialize the underlying cipher
            evpCipher = OpenSSLCrypto.EVP_get_cipherbyname(opensslCipherName, arena);
            if (evpCipher == null || evpCipher.address() == 0) {
                throw new ProviderException("Failed to get cipher: " + opensslCipherName);
            }

            evpCipherCtx = OpenSSLCrypto.EVP_CIPHER_CTX_new();
            if (evpCipherCtx == null || evpCipherCtx.address() == 0) {
                throw new ProviderException("Failed to create EVP_CIPHER_CTX");
            }

            MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, derivedKey.length);
            keySegment.asByteBuffer().put(derivedKey);

            MemorySegment ivSegment;
            if (iv != null) {
                ivSegment = arena.allocate(ValueLayout.JAVA_BYTE, iv.length);
                ivSegment.asByteBuffer().put(iv);
            } else {
                ivSegment = MemorySegment.NULL;
            }

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptInit_ex(evpCipherCtx, evpCipher, MemorySegment.NULL, keySegment, ivSegment);
            } else {
                result = OpenSSLCrypto.EVP_DecryptInit_ex(evpCipherCtx, evpCipher, MemorySegment.NULL, keySegment, ivSegment);
            }

            if (result != 1) {
                throw new InvalidKeyException("Cipher initialization failed");
            }

        } catch (Throwable e) {
            throw new ProviderException("Error initializing PBE cipher", e);
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
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment inputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, inputLen);
            inputSegment.asByteBuffer().put(input, inputOffset, inputLen);

            MemorySegment outputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, output.length - outputOffset);
            MemorySegment outLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT);

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptUpdate(evpCipherCtx, outputSegment, outLenSegment, inputSegment, inputLen);
            } else {
                result = OpenSSLCrypto.EVP_DecryptUpdate(evpCipherCtx, outputSegment, outLenSegment, inputSegment, inputLen);
            }

            if (result != 1) {
                throw new ProviderException("Cipher update failed");
            }

            int written = outLenSegment.get(ValueLayout.JAVA_INT, 0);
            outputSegment.asByteBuffer().get(output, outputOffset, written);
            return written;
        } catch (Throwable e) {
            throw new ProviderException("Error updating cipher", e);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        try (Arena confinedArena = Arena.ofConfined()) {
            // Step 1: Process any remaining input
            int currentUpdateOutputLen = 0;
            MemorySegment currentUpdateOutputSegment = MemorySegment.NULL;

            if (input != null && inputLen > 0) {
                int conservativeOutputSize = inputLen + engineGetBlockSize();
                currentUpdateOutputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, conservativeOutputSize);
                MemorySegment currentOutLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT);

                MemorySegment inputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, inputLen);
                inputSegment.asByteBuffer().put(input, inputOffset, inputLen);

                int result;
                if (opmode == Cipher.ENCRYPT_MODE) {
                    result = OpenSSLCrypto.EVP_EncryptUpdate(evpCipherCtx, currentUpdateOutputSegment, currentOutLenSegment, inputSegment, inputLen);
                } else {
                    result = OpenSSLCrypto.EVP_DecryptUpdate(evpCipherCtx, currentUpdateOutputSegment, currentOutLenSegment, inputSegment, inputLen);
                }
                if (result != 1) {
                    throw new ProviderException("Cipher update failed in engineDoFinal");
                }
                currentUpdateOutputLen = currentOutLenSegment.get(ValueLayout.JAVA_INT, 0);
            }

            // Step 2: Finalize
            int finalOutputSegmentSize = engineGetOutputSize(0);
            MemorySegment finalOutputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, finalOutputSegmentSize);
            MemorySegment finalOutLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT);

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptFinal_ex(evpCipherCtx, finalOutputSegment, finalOutLenSegment);
            } else {
                result = OpenSSLCrypto.EVP_DecryptFinal_ex(evpCipherCtx, finalOutputSegment, finalOutLenSegment);
            }

            if (result != 1) {
                if (opmode == Cipher.ENCRYPT_MODE) {
                    throw new ProviderException("Cipher finalization failed");
                } else {
                    throw new BadPaddingException("Cipher finalization failed");
                }
            }

            int finalCiphertextLen = finalOutLenSegment.get(ValueLayout.JAVA_INT, 0);

            // Step 3: Combine outputs
            byte[] outputFromCurrentUpdate = (currentUpdateOutputLen > 0)
                ? currentUpdateOutputSegment.asSlice(0, currentUpdateOutputLen).toArray(ValueLayout.JAVA_BYTE)
                : new byte[0];
            byte[] outputFromFinal = (finalCiphertextLen > 0)
                ? finalOutputSegment.asSlice(0, finalCiphertextLen).toArray(ValueLayout.JAVA_BYTE)
                : new byte[0];

            byte[] finalOutput = new byte[outputFromCurrentUpdate.length + outputFromFinal.length];
            System.arraycopy(outputFromCurrentUpdate, 0, finalOutput, 0, outputFromCurrentUpdate.length);
            System.arraycopy(outputFromFinal, 0, finalOutput, outputFromCurrentUpdate.length, outputFromFinal.length);

            return finalOutput;

        } catch (Throwable e) {
            throw new ProviderException("Error finalizing cipher", e);
        } finally {
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
        if (evpCipherCtx != null) {
            try {
                OpenSSLCrypto.EVP_CIPHER_CTX_free(evpCipherCtx);
            } catch (Throwable e) {
                // Ignore
            }
            evpCipherCtx = null;
        }
        if (derivedKey != null) {
            java.util.Arrays.fill(derivedKey, (byte) 0);
            derivedKey = null;
        }
    }
}
