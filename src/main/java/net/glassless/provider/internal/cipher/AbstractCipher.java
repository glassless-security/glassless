package net.glassless.provider.internal.cipher;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import net.glassless.provider.internal.NativeResourceCleaner;
import net.glassless.provider.internal.OpenSSLCrypto;

abstract class AbstractCipher extends CipherSpi {

   protected final Arena arena;
   private String algorithmName;
   private final CipherMode mode;
   private final CipherPadding padding;
   protected final NativeResourceCleaner.ResourceHolder resourceHolder;
   private int gcmTagLenBits; // New field for GCM tag length in bits

   protected MemorySegment evpCipherCtx;
   protected MemorySegment evpCipher;
   protected int opmode;
   protected byte[] iv;

   protected AbstractCipher(String algorithmName, CipherMode mode, CipherPadding padding) {
      this.algorithmName = algorithmName;
      this.mode = mode;
      this.padding = padding;
      this.arena = Arena.ofShared();
      this.gcmTagLenBits = 128; // Default to 128 bits for GCM
      // Register cleanup for when this object is GC'd
      this.resourceHolder = NativeResourceCleaner.createHolder(this);
      this.resourceHolder.setArena(arena);
   }

   protected void setAlgorithmName(String algorithmName) {
      this.algorithmName = algorithmName;
   }

   /**
    * Called during engineInit to allow subclasses to resolve the OpenSSL algorithm
    * name based on the key. Default implementation does nothing.
    */
   protected void resolveAlgorithm(Key key) throws InvalidKeyException {
      // Override in subclasses that need to determine algorithm from key size
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
      boolean isAEAD = mode == CipherMode.GCM || mode == CipherMode.GCM_SIV || mode == CipherMode.CCM || mode == CipherMode.POLY1305;
      if (isAEAD) {
         int tagLength = gcmTagLenBits / 8;
         if (opmode == Cipher.ENCRYPT_MODE) {
            // Ciphertext + tag
            return inputLen + tagLength;
         } else {
            // Input includes the tag; plaintext is smaller
            return Math.max(0, inputLen - tagLength);
         }
      }
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
      // Clean up any previous cipher context
      reset();

      this.opmode = opmode;

      if (params instanceof IvParameterSpec ivParams) {
         this.iv = ivParams.getIV();
      } else if (params instanceof GCMParameterSpec gcmParams) {
         this.iv = gcmParams.getIV();
         this.gcmTagLenBits = gcmParams.getTLen();
      } else if (params != null) {
         throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + params.getClass().getName());
      }

      try {
         resolveAlgorithm(key);
         evpCipher = OpenSSLCrypto.EVP_get_cipherbyname(algorithmName, arena);
         if (evpCipher.equals(MemorySegment.NULL)) {
            // Fall back to EVP_CIPHER_fetch for newer ciphers (e.g., AES-GCM-SIV)
            evpCipher = OpenSSLCrypto.EVP_CIPHER_fetch(MemorySegment.NULL, algorithmName, MemorySegment.NULL, arena);
         }
         if (evpCipher.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to get cipher: " + algorithmName);
         }

         evpCipherCtx = OpenSSLCrypto.EVP_CIPHER_CTX_new();
         if (evpCipherCtx.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to create EVP_CIPHER_CTX");
         }
         // Track context for cleanup on GC
         resourceHolder.setEvpCipherCtx(evpCipherCtx);

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
         if (padding == CipherPadding.NOPADDING && mode != CipherMode.GCM && mode != CipherMode.GCM_SIV && mode != CipherMode.CCM && mode != CipherMode.POLY1305) {
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
      if (params == null) {
         engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
         return;
      }
      AlgorithmParameterSpec paramSpec = extractParameterSpec(params);
      engineInit(opmode, key, paramSpec, random);
   }

   /**
    * Extracts the appropriate AlgorithmParameterSpec from AlgorithmParameters.
    * Subclasses (e.g., PBE ciphers) can override to extract their specific spec type.
    */
   protected AlgorithmParameterSpec extractParameterSpec(AlgorithmParameters params)
      throws InvalidAlgorithmParameterException {
      try {
         if (mode == CipherMode.GCM) {
            return params.getParameterSpec(GCMParameterSpec.class);
         }
         return params.getParameterSpec(IvParameterSpec.class);
      } catch (InvalidParameterSpecException e) {
         throw new InvalidAlgorithmParameterException("Failed to extract parameter spec", e);
      }
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
   protected int engineUpdate(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
      int inputLen = input.remaining();
      if (inputLen == 0) {
         return 0;
      }
      byte[] inputBytes = new byte[inputLen];
      input.get(inputBytes);
      // Allocate based on what OpenSSL can actually produce: at most inputLen + one block
      int maxOutput = inputLen + engineGetBlockSize();
      byte[] outputBytes = new byte[maxOutput];
      int written = engineUpdate(inputBytes, 0, inputLen, outputBytes, 0);
      if (written > output.remaining()) {
         throw new ShortBufferException("Output buffer too small: need " + written + " but have " + output.remaining());
      }
      output.put(outputBytes, 0, written);
      return written;
   }

   @Override
   protected void engineUpdateAAD(byte[] src, int offset, int len) {
      if (evpCipherCtx == null) {
         throw new IllegalStateException("Cipher not initialized");
      }
      try (Arena confinedArena = Arena.ofConfined()) {
         MemorySegment inputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, len);
         inputSegment.asByteBuffer().put(src, offset, len);

         MemorySegment outLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT);

         int result;
         if (opmode == Cipher.ENCRYPT_MODE) {
            result = OpenSSLCrypto.EVP_EncryptUpdate(evpCipherCtx, MemorySegment.NULL, outLenSegment, inputSegment, len);
         } else {
            result = OpenSSLCrypto.EVP_DecryptUpdate(evpCipherCtx, MemorySegment.NULL, outLenSegment, inputSegment, len);
         }
         if (result != 1) {
            throw new ProviderException("Failed to update AAD");
         }
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error updating AAD", e);
      }
   }

   @Override
   protected void engineUpdateAAD(ByteBuffer src) {
      int len = src.remaining();
      if (len == 0) {
         return;
      }
      byte[] aad = new byte[len];
      src.get(aad);
      engineUpdateAAD(aad, 0, aad.length);
   }

   @Override
   protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
      try (Arena confinedArena = Arena.ofConfined()) {
         int tagLength = gcmTagLenBits / 8; // Convert bits to bytes

         // Step 1: Process any remaining input that came with this engineDoFinal call
         int currentUpdateOutputLen = 0;
         MemorySegment currentUpdateOutputSegment = MemorySegment.NULL;

         boolean isAEAD = mode == CipherMode.GCM || mode == CipherMode.GCM_SIV || mode == CipherMode.CCM || mode == CipherMode.POLY1305;
         if (input != null && inputLen > 0) {
            int actualInputLen = inputLen;

            // For AEAD decryption (GCM, CCM, POLY1305), the input is (ciphertext || tag)
            // We need to extract the tag and only pass the ciphertext to DecryptUpdate
            if (opmode == Cipher.DECRYPT_MODE && isAEAD) {
               if (inputLen < tagLength) {
                  throw new BadPaddingException("GCM input too short to contain tag");
               }
               // Extract tag from the end of input
               MemorySegment inputTagSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, tagLength);
               inputTagSegment.asByteBuffer().put(input, inputOffset + inputLen - tagLength, tagLength);
               int setTagResult = OpenSSLCrypto.EVP_CIPHER_CTX_ctrl(evpCipherCtx, 0x11, tagLength, inputTagSegment); // 0x11 is EVP_CTRL_GCM_SET_TAG
               if (setTagResult <= 0) {
                  throw new BadPaddingException("Failed to set AEAD tag");
               }

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


         int finalOutputSegmentSize = Math.max(engineGetBlockSize(), 16); // At least one block for final output
         MemorySegment finalOutputSegment = confinedArena.allocate(ValueLayout.JAVA_BYTE, finalOutputSegmentSize);
         MemorySegment finalOutLenSegment = confinedArena.allocate(ValueLayout.JAVA_INT);

         int result;
         if (opmode == Cipher.ENCRYPT_MODE) {
            result = OpenSSLCrypto.EVP_EncryptFinal_ex(evpCipherCtx, finalOutputSegment, finalOutLenSegment);
            finalCiphertextLen = finalOutLenSegment.get(ValueLayout.JAVA_INT, 0);

            if (result == 1 && isAEAD) {
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

      } catch (IllegalBlockSizeException | BadPaddingException e) {
         throw e;
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

   protected void reset() {
      if (evpCipherCtx != null) {
         try {
            OpenSSLCrypto.EVP_CIPHER_CTX_free(evpCipherCtx);
         } catch (Throwable e) {
            // Ignore
         }
         evpCipherCtx = null;
         resourceHolder.clearEvpCipherCtx();
      }
   }
}
