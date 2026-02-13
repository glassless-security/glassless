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
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

abstract class AbstractCipher extends CipherSpi {

    private final Arena arena;
    private final String algorithmName;
    private final int keySize;
    private final CipherMode mode;
    private final CipherPadding padding;
    private int gcmTagLenBits; // New field for GCM tag length in bits

    private MemorySegment evpCipherCtx;
    private MemorySegment evpCipher;
    private int opmode;
    private byte[] iv;
    private Key key;

    protected AbstractCipher(String algorithmName, int keySize, CipherMode mode, CipherPadding padding) {
        this.algorithmName = algorithmName;
        this.keySize = keySize;
        this.mode = mode;
        this.padding = padding;
        this.arena = Arena.ofShared();
        this.gcmTagLenBits = 128; // Default to 128 bits for GCM
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!this.mode.name().equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!this.padding.name().equalsIgnoreCase(padding.replace("PADDING", "Padding"))) {
            throw new NoSuchPaddingException("Unsupported padding: " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        try {
            return OpenSSLCrypto.EVP_CIPHER_get_block_size(evpCipher);
        } catch (Throwable e) {
            throw new ProviderException(e);
        }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // This is a conservative estimate. The actual size may be smaller.
        return inputLen + engineGetBlockSize();
    }

    @Override
    protected byte[] engineGetIV() {
        return this.iv == null ? null : this.iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // Not implemented
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // This should not happen
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;
        this.key = key;

        if (params instanceof IvParameterSpec) {
            this.iv = ((IvParameterSpec) params).getIV();
        } else if (params instanceof GCMParameterSpec gcmParams) {
           this.iv = gcmParams.getIV();
            this.gcmTagLenBits = gcmParams.getTLen();
        } else if (params != null) {
            throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + params.getClass().getName());
        }

        try {
            evpCipher = OpenSSLCrypto.EVP_get_cipherbyname(algorithmName, arena);
            if (evpCipher == null || evpCipher.address() == 0) {
                throw new ProviderException("Failed to get cipher: " + algorithmName);
            }

            evpCipherCtx = OpenSSLCrypto.EVP_CIPHER_CTX_new();
            if (evpCipherCtx == null || evpCipherCtx.address() == 0) {
                throw new ProviderException("Failed to create EVP_CIPHER_CTX");
            }

            byte[] keyBytes = key.getEncoded();
            MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
            keySegment.asByteBuffer().put(keyBytes);

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



            // Disable padding if NOPADDING is specified and mode is not AEAD (GCM, CCM or POLY1305)
            if (padding == CipherPadding.NOPADDING && mode != CipherMode.GCM && mode != CipherMode.CCM && mode != CipherMode.POLY1305) {
                result = OpenSSLCrypto.EVP_CIPHER_CTX_set_padding(evpCipherCtx, 0);
                if (result != 1) {
                    throw new ProviderException("Failed to set NOPADDING");
                }
            }

        } catch (Throwable e) {
            throw new ProviderException("Error initializing cipher", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Not implemented
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
            // Should not happen with our output size estimate
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
            MemorySegment outLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT); // Corrected: Allocate space for an int

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
            int tagLength = gcmTagLenBits / 8; // Convert bits to bytes

            // Step 1: Process any remaining input that came with this engineDoFinal call
            int currentUpdateOutputLen = 0;
            MemorySegment currentUpdateOutputSegment = MemorySegment.NULL;

            if (input != null && inputLen > 0) {
                int actualInputLen = inputLen;

                // For AEAD decryption (GCM, CCM, POLY1305), the input is (ciphertext || tag)
                // We need to extract the tag and only pass the ciphertext to DecryptUpdate
                if (opmode == Cipher.DECRYPT_MODE && (mode == CipherMode.GCM || mode == CipherMode.CCM || mode == CipherMode.POLY1305)) {
                    if (inputLen < tagLength) {
                        throw new BadPaddingException("GCM input too short to contain tag");
                    }
                    // Extract tag from the end of input
                    MemorySegment inputTagSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, tagLength);
                    inputTagSegment.asByteBuffer().put(input, inputOffset + inputLen - tagLength, tagLength);
                    OpenSSLCrypto.EVP_CIPHER_CTX_ctrl(evpCipherCtx, 0x11, tagLength, inputTagSegment); // 0x11 is EVP_CTRL_GCM_SET_TAG

                    // Adjust input length to exclude the tag
                    actualInputLen = inputLen - tagLength;
                }

                // Determine conservative output size for this update operation
                int conservativeOutputSize = actualInputLen + engineGetBlockSize();
                currentUpdateOutputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, conservativeOutputSize);
                MemorySegment currentOutLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT);

                MemorySegment inputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, actualInputLen);
                inputSegment.asByteBuffer().put(input, inputOffset, actualInputLen);

                int result;
                if (opmode == Cipher.ENCRYPT_MODE) {
                    result = OpenSSLCrypto.EVP_EncryptUpdate(evpCipherCtx, currentUpdateOutputSegment, currentOutLenSegment, inputSegment, actualInputLen);
                } else {
                    result = OpenSSLCrypto.EVP_DecryptUpdate(evpCipherCtx, currentUpdateOutputSegment, currentOutLenSegment, inputSegment, actualInputLen);
                }
                if (result != 1) {
                    throw new ProviderException("Cipher update failed in engineDoFinal");
                }
                currentUpdateOutputLen = currentOutLenSegment.get(ValueLayout.JAVA_INT, 0);
            }

            // Step 2: Finalize the cipher operation with EVP_Final_ex
            int finalCiphertextLen = 0;
            MemorySegment tagSegment = MemorySegment.NULL;


            int finalOutputSegmentSize = engineGetOutputSize(0); // Max possible for final, like one block
            MemorySegment finalOutputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, finalOutputSegmentSize);
            MemorySegment finalOutLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT);

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptFinal_ex(evpCipherCtx, finalOutputSegment, finalOutLenSegment);
                finalCiphertextLen = finalOutLenSegment.get(ValueLayout.JAVA_INT, 0);

                if (result == 1 && (mode == CipherMode.GCM || mode == CipherMode.CCM || mode == CipherMode.POLY1305)) {
                    // Retrieve AEAD tag (GCM, CCM or Poly1305)
                    tagSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, tagLength);
                    int getTagResult = OpenSSLCrypto.EVP_CIPHER_CTX_ctrl(evpCipherCtx, 0x10, tagLength, tagSegment); // 0x10 is EVP_CTRL_GCM_GET_TAG
                    if (getTagResult != 1) {
                        throw new ProviderException("Failed to get GCM tag");
                    }
                }
            } else { // Decrypt mode
                result = OpenSSLCrypto.EVP_DecryptFinal_ex(evpCipherCtx, finalOutputSegment, finalOutLenSegment);
                finalCiphertextLen = finalOutLenSegment.get(ValueLayout.JAVA_INT, 0);
            }

            if (result != 1) {
                if (opmode == Cipher.ENCRYPT_MODE) {
                    throw new ProviderException("Cipher finalization failed");
                } else {
                    throw new BadPaddingException("Cipher finalization failed");
                }
            }

            // Step 3: Combine all outputs
            byte[] outputFromCurrentUpdate = (currentUpdateOutputLen > 0) ? currentUpdateOutputSegment.asSlice(0, currentUpdateOutputLen).toArray(ValueLayout.JAVA_BYTE) : new byte[0];
            byte[] outputFromFinal = (finalCiphertextLen > 0) ? finalOutputSegment.asSlice(0, finalCiphertextLen).toArray(ValueLayout.JAVA_BYTE) : new byte[0];
            byte[] gcmTagBytes = (tagSegment != MemorySegment.NULL) ? tagSegment.toArray(ValueLayout.JAVA_BYTE) : new byte[0];

            int totalOutputArrayLen = outputFromCurrentUpdate.length + outputFromFinal.length + gcmTagBytes.length;
            byte[] finalOutput = new byte[totalOutputArrayLen];
            int currentOffset = 0;

            System.arraycopy(outputFromCurrentUpdate, 0, finalOutput, currentOffset, outputFromCurrentUpdate.length);
            currentOffset += outputFromCurrentUpdate.length;
            System.arraycopy(outputFromFinal, 0, finalOutput, currentOffset, outputFromFinal.length);
            currentOffset += outputFromFinal.length;
            System.arraycopy(gcmTagBytes, 0, finalOutput, currentOffset, gcmTagBytes.length);

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
    }
}
