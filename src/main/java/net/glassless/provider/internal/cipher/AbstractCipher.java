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
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

abstract class AbstractCipher extends CipherSpi {

    private final String algorithmName;
    private final int keySize;
    private final CipherMode mode;
    private final CipherPadding padding;
    private int gcmTagLenBits; // New field for GCM tag length in bits

    private int evpCipherCtx;
    private int evpCipher;
    private int opmode;
    private byte[] iv;
    private Key key;

    protected AbstractCipher(String algorithmName, int keySize, CipherMode mode, CipherPadding padding) {
        this.algorithmName = algorithmName;
        this.keySize = keySize;
        this.mode = mode;
        this.padding = padding;
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

        int keyPtr = 0;
        int ivPtr = 0;
        try {
            evpCipher = OpenSSLCrypto.EVP_get_cipherbyname(algorithmName);
            if (evpCipher == 0) {
                throw new ProviderException("Failed to get cipher: " + algorithmName);
            }

            evpCipherCtx = OpenSSLCrypto.EVP_CIPHER_CTX_new();
            if (evpCipherCtx == 0) {
                throw new ProviderException("Failed to create EVP_CIPHER_CTX");
            }

            byte[] keyBytes = key.getEncoded();
            keyPtr = OpenSSLCrypto.malloc(keyBytes.length);
            OpenSSLCrypto.memory().write(keyPtr, keyBytes);

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



            // Disable padding if NOPADDING is specified and mode is not AEAD (GCM, CCM or POLY1305)
            if (padding == CipherPadding.NOPADDING && mode != CipherMode.GCM && mode != CipherMode.CCM && mode != CipherMode.POLY1305) {
                result = OpenSSLCrypto.EVP_CIPHER_CTX_set_padding(evpCipherCtx, 0);
                if (result != 1) {
                    throw new ProviderException("Failed to set NOPADDING");
                }
            }

        } catch (Throwable e) {
            throw new ProviderException("Error initializing cipher", e);
        } finally {
            OpenSSLCrypto.free(keyPtr);
            OpenSSLCrypto.free(ivPtr);
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
        int inputTagPtr = 0;
        int currentUpdateOutputPtr = 0;
        int currentOutLenPtr = 0;
        int inputPtr = 0;
        int finalOutputPtr = 0;
        int finalOutLenPtr = 0;
        int tagPtr = 0;
        try {
            int tagLength = gcmTagLenBits / 8; // Convert bits to bytes

            // Step 1: Process any remaining input that came with this engineDoFinal call
            int currentUpdateOutputLen = 0;

            if (input != null && inputLen > 0) {
                int actualInputLen = inputLen;

                // For AEAD decryption (GCM, CCM, POLY1305), the input is (ciphertext || tag)
                // We need to extract the tag and only pass the ciphertext to DecryptUpdate
                if (opmode == Cipher.DECRYPT_MODE && (mode == CipherMode.GCM || mode == CipherMode.CCM || mode == CipherMode.POLY1305)) {
                    if (inputLen < tagLength) {
                        throw new BadPaddingException("GCM input too short to contain tag");
                    }
                    // Extract tag from the end of input
                    inputTagPtr = OpenSSLCrypto.malloc(tagLength);
                    OpenSSLCrypto.memory().write(inputTagPtr, input, inputOffset + inputLen - tagLength, tagLength);
                    OpenSSLCrypto.EVP_CIPHER_CTX_ctrl(evpCipherCtx, 0x11, tagLength, inputTagPtr); // 0x11 is EVP_CTRL_GCM_SET_TAG

                    // Adjust input length to exclude the tag
                    actualInputLen = inputLen - tagLength;
                }

                // Determine conservative output size for this update operation
                int conservativeOutputSize = actualInputLen + engineGetBlockSize();
                currentUpdateOutputPtr = OpenSSLCrypto.malloc(conservativeOutputSize);
                currentOutLenPtr = OpenSSLCrypto.malloc(4);

                inputPtr = OpenSSLCrypto.malloc(actualInputLen);
                OpenSSLCrypto.memory().write(inputPtr, input, inputOffset, actualInputLen);

                int result;
                if (opmode == Cipher.ENCRYPT_MODE) {
                    result = OpenSSLCrypto.EVP_EncryptUpdate(evpCipherCtx, currentUpdateOutputPtr, currentOutLenPtr, inputPtr, actualInputLen);
                } else {
                    result = OpenSSLCrypto.EVP_DecryptUpdate(evpCipherCtx, currentUpdateOutputPtr, currentOutLenPtr, inputPtr, actualInputLen);
                }
                if (result != 1) {
                    throw new ProviderException("Cipher update failed in engineDoFinal");
                }
                currentUpdateOutputLen = OpenSSLCrypto.memory().readInt(currentOutLenPtr);
            }

            // Step 2: Finalize the cipher operation with EVP_Final_ex
            int finalCiphertextLen = 0;

            int finalOutputSegmentSize = engineGetOutputSize(0); // Max possible for final, like one block
            finalOutputPtr = OpenSSLCrypto.malloc(finalOutputSegmentSize);
            finalOutLenPtr = OpenSSLCrypto.malloc(4);

            int result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLCrypto.EVP_EncryptFinal_ex(evpCipherCtx, finalOutputPtr, finalOutLenPtr);
                finalCiphertextLen = OpenSSLCrypto.memory().readInt(finalOutLenPtr);

                if (result == 1 && (mode == CipherMode.GCM || mode == CipherMode.CCM || mode == CipherMode.POLY1305)) {
                    // Retrieve AEAD tag (GCM, CCM or Poly1305)
                    tagPtr = OpenSSLCrypto.malloc(tagLength);
                    int getTagResult = OpenSSLCrypto.EVP_CIPHER_CTX_ctrl(evpCipherCtx, 0x10, tagLength, tagPtr); // 0x10 is EVP_CTRL_GCM_GET_TAG
                    if (getTagResult != 1) {
                        throw new ProviderException("Failed to get GCM tag");
                    }
                }
            } else { // Decrypt mode
                result = OpenSSLCrypto.EVP_DecryptFinal_ex(evpCipherCtx, finalOutputPtr, finalOutLenPtr);
                finalCiphertextLen = OpenSSLCrypto.memory().readInt(finalOutLenPtr);
            }

            if (result != 1) {
                if (opmode == Cipher.ENCRYPT_MODE) {
                    throw new ProviderException("Cipher finalization failed");
                } else {
                    throw new BadPaddingException("Cipher finalization failed");
                }
            }

            // Step 3: Combine all outputs
            byte[] outputFromCurrentUpdate = (currentUpdateOutputLen > 0) ? OpenSSLCrypto.memory().readBytes(currentUpdateOutputPtr, currentUpdateOutputLen) : new byte[0];
            byte[] outputFromFinal = (finalCiphertextLen > 0) ? OpenSSLCrypto.memory().readBytes(finalOutputPtr, finalCiphertextLen) : new byte[0];
            byte[] gcmTagBytes = (tagPtr != 0) ? OpenSSLCrypto.memory().readBytes(tagPtr, tagLength) : new byte[0];

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
            OpenSSLCrypto.free(inputTagPtr);
            OpenSSLCrypto.free(currentUpdateOutputPtr);
            OpenSSLCrypto.free(currentOutLenPtr);
            OpenSSLCrypto.free(inputPtr);
            OpenSSLCrypto.free(finalOutputPtr);
            OpenSSLCrypto.free(finalOutLenPtr);
            OpenSSLCrypto.free(tagPtr);
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
    }
}
