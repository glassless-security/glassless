package net.glassless.provider.internal.digest;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.MessageDigestSpi;
import java.security.ProviderException;
import java.util.Objects;

import net.glassless.provider.internal.OpenSSLCrypto;

public abstract class AbstractDigest extends MessageDigestSpi implements Cloneable {

   private final MemorySegment evpMdCtx;
   private final MemorySegment handle;
   private final Arena arena;

   protected AbstractDigest(String algorithmName) throws ProviderException {
      super();
      try {
         arena = Arena.ofShared();
         evpMdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
         if (evpMdCtx.address() == 0) {
            throw new ProviderException("Failed to create EVP_MD_CTX");
         }
         handle = OpenSSLCrypto.getDigestHandle(algorithmName, arena);
         if (handle.address() == 0) {
            throw new ProviderException("Failed to get " + algorithmName + " EVP_MD");
         }
         engineReset();
      } catch (Throwable e) {
         throw new ProviderException("Error initializing " + this.getClass().getSimpleName(), e);
      }
   }

   @Override
   protected void engineUpdate(byte input) {
      try {
         MemorySegment inputSegment = arena.allocate(1);
         inputSegment.set(java.lang.foreign.ValueLayout.JAVA_BYTE, 0, input);
         int result = OpenSSLCrypto.EVP_DigestUpdate(evpMdCtx, inputSegment, 1);
         if (result != 1) {
            throw new ProviderException("EVP_DigestUpdate failed for single byte");
         }
      } catch (Throwable e) {
         throw new ProviderException("Error updating digest with single byte", e);
      }
   }

   @Override
   protected void engineUpdate(byte[] input, int offset, int len) {
      Objects.requireNonNull(input, "Input array cannot be null");
      if (offset < 0 || len < 0 || (long) offset + len > input.length) {
         throw new IndexOutOfBoundsException("Illegal offset or len: offset=" + offset + ", len=" + len + ", input.length=" + input.length);
      }
      if (len == 0) {
         return;
      }

      try {
         MemorySegment inputSegment = arena.allocate(java.lang.foreign.ValueLayout.JAVA_BYTE, len);
         inputSegment.asByteBuffer().put(input, offset, len);
         int result = OpenSSLCrypto.EVP_DigestUpdate(evpMdCtx, inputSegment, len);
         if (result != 1) {
            throw new ProviderException("EVP_DigestUpdate failed");
         }
      } catch (Throwable e) {
         throw new ProviderException("Error updating digest", e);
      }
   }

   @Override
   protected byte[] engineDigest() {
      try (Arena confinedArena = Arena.ofConfined()) {
         int digestSize = OpenSSLCrypto.EVP_MD_size(handle);
         if (digestSize <= 0) {
            throw new ProviderException("Invalid digest size: " + digestSize);
         }

         MemorySegment digestBuffer = confinedArena.allocate(ValueLayout.JAVA_BYTE, digestSize);
         MemorySegment digestLenPtr = confinedArena.allocate(ValueLayout.JAVA_INT);
         digestLenPtr.set(ValueLayout.JAVA_INT, 0, digestSize);

         MemorySegment tempEvpMdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
         if (tempEvpMdCtx.address() == 0) {
            throw new ProviderException("Failed to duplicate EVP_MD_CTX for finalization");
         }
         int result = OpenSSLCrypto.EVP_DigestFinal_ex(evpMdCtx, digestBuffer, digestLenPtr);
         if (result != 1) {
            throw new ProviderException("EVP_DigestFinal_ex failed");
         }
         byte[] digest = digestBuffer.asSlice(0, digestSize).toArray(ValueLayout.JAVA_BYTE);
         engineReset();
         return digest;
      } catch (Throwable e) {
         throw new ProviderException("Error calculating digest", e);
      }
   }

   @Override
   protected int engineGetDigestLength() {
      try {
         return OpenSSLCrypto.EVP_MD_size(handle);
      } catch (Throwable e) {
         throw new ProviderException("Error getting digest length", e);
      }
   }

   @Override
   protected void engineReset() {
      try {
         int result = OpenSSLCrypto.EVP_DigestInit_ex(evpMdCtx, handle);
         if (result != 1) {
            throw new ProviderException("EVP_DigestInit_ex failed during reset");
         }
      } catch (Throwable e) {
         throw new ProviderException("Error resetting digest", e);
      }
   }

   @Override
   public Object clone() throws CloneNotSupportedException {
      // TODO
      throw new CloneNotSupportedException(this.getClass().getSimpleName() + " does not support cloning yet.");
   }
}
