package net.glassless.provider.internal.cipher;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
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

    private final Arena arena;
    private final RSAPadding padding;
    private final String oaepDigest; // For OAEP padding, null otherwise

    private MemorySegment evpPkey;
    private MemorySegment evpPkeyCtx;
    private int opmode;
    private int keySize; // in bytes

    protected AbstractRSACipher(RSAPadding padding, String oaepDigest) {
        this.padding = padding;
        this.oaepDigest = oaepDigest;
        this.arena = Arena.ofShared();
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

            // Create memory segment for key bytes
            MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
            keySegment.asByteBuffer().put(keyBytes);

            // Create a pointer to the key data (OpenSSL modifies the pointer)
            MemorySegment keyPtrSegment = arena.allocate(ValueLayout.ADDRESS);
            keyPtrSegment.set(ValueLayout.ADDRESS, 0, keySegment);

            // Load the key using d2i_PrivateKey or d2i_PUBKEY
            if (key instanceof PrivateKey) {
                evpPkey = OpenSSLCrypto.d2i_PrivateKey(OpenSSLCrypto.EVP_PKEY_RSA, MemorySegment.NULL, keyPtrSegment, keyBytes.length);
            } else if (key instanceof PublicKey) {
                evpPkey = OpenSSLCrypto.d2i_PUBKEY(MemorySegment.NULL, keyPtrSegment, keyBytes.length);
            } else {
                throw new InvalidKeyException("Key must be a PublicKey or PrivateKey");
            }

            if (evpPkey == null || evpPkey.address() == 0) {
                throw new InvalidKeyException("Failed to load RSA key");
            }

            // Create EVP_PKEY_CTX
            evpPkeyCtx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(MemorySegment.NULL, evpPkey, MemorySegment.NULL);
            if (evpPkeyCtx == null || evpPkeyCtx.address() == 0) {
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
                MemorySegment digestHandle = OpenSSLCrypto.getDigestHandle(oaepDigest, arena);
                if (digestHandle == null || digestHandle.address() == 0) {
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

        try (Arena confinedArena = Arena.ofConfined()) {
            // Allocate input buffer
            MemorySegment inputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, inputLen);
            inputSegment.asByteBuffer().put(input, inputOffset, inputLen);

            // Allocate output length segment
            MemorySegment outLenSegment = confinedArena.allocate(ValueLayout.JAVA_LONG);

            int result;

            if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
                // First call to get output size
                result = OpenSSLCrypto.EVP_PKEY_encrypt(evpPkeyCtx, MemorySegment.NULL, outLenSegment, inputSegment, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA encryption failed (size query)");
                }

                long outLen = outLenSegment.get(ValueLayout.JAVA_LONG, 0);
                MemorySegment outputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, outLen);

                // Actual encryption
                result = OpenSSLCrypto.EVP_PKEY_encrypt(evpPkeyCtx, outputSegment, outLenSegment, inputSegment, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA encryption failed");
                }

                outLen = outLenSegment.get(ValueLayout.JAVA_LONG, 0);
                byte[] output = new byte[(int) outLen];
                outputSegment.asByteBuffer().get(output);
                return output;

            } else {
                // First call to get output size
                result = OpenSSLCrypto.EVP_PKEY_decrypt(evpPkeyCtx, MemorySegment.NULL, outLenSegment, inputSegment, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA decryption failed (size query)");
                }

                long outLen = outLenSegment.get(ValueLayout.JAVA_LONG, 0);
                MemorySegment outputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, outLen);

                // Actual decryption
                result = OpenSSLCrypto.EVP_PKEY_decrypt(evpPkeyCtx, outputSegment, outLenSegment, inputSegment, inputLen);
                if (result <= 0) {
                    throw new BadPaddingException("RSA decryption failed");
                }

                outLen = outLenSegment.get(ValueLayout.JAVA_LONG, 0);
                byte[] output = new byte[(int) outLen];
                outputSegment.asByteBuffer().get(output);
                return output;
            }

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw e;
        } catch (Throwable e) {
            throw new ProviderException("Error in RSA operation", e);
        } finally {
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
        if (evpPkeyCtx != null) {
            try {
                OpenSSLCrypto.EVP_PKEY_CTX_free(evpPkeyCtx);
            } catch (Throwable e) {
                // Ignore
            }
            evpPkeyCtx = null;
        }
        if (evpPkey != null) {
            try {
                OpenSSLCrypto.EVP_PKEY_free(evpPkey);
            } catch (Throwable e) {
                // Ignore
            }
            evpPkey = null;
        }
    }
}
