package net.glassless.provider.internal.digest;

import java.security.MessageDigestSpi;
import java.security.ProviderException;
import java.util.Objects;

import net.glassless.provider.internal.OpenSSLCrypto;

public abstract class AbstractDigest extends MessageDigestSpi implements Cloneable {

   private final int evpMdCtx;
   private final int handle;

   protected AbstractDigest(String algorithmName) throws ProviderException {
      super();
      try {
         evpMdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
         if (evpMdCtx == 0) {
            throw new ProviderException("Failed to create EVP_MD_CTX");
         }
         handle = OpenSSLCrypto.getDigestHandle(algorithmName);
         if (handle == 0) {
            throw new ProviderException("Failed to get " + algorithmName + " EVP_MD");
         }
         engineReset();
      } catch (Throwable e) {
         throw new ProviderException("Error initializing " + this.getClass().getSimpleName(), e);
      }
   }

   @Override
   protected void engineUpdate(byte input) {
      int inputPtr = 0;
      try {
         inputPtr = OpenSSLCrypto.malloc(1);
         OpenSSLCrypto.memory().writeByte(inputPtr, input);
         int result = OpenSSLCrypto.EVP_DigestUpdate(evpMdCtx, inputPtr, 1);
         if (result != 1) {
            throw new ProviderException("EVP_DigestUpdate failed for single byte");
         }
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error updating digest with single byte", e);
      } finally {
         OpenSSLCrypto.free(inputPtr);
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

      int inputPtr = 0;
      try {
         inputPtr = OpenSSLCrypto.malloc(len);
         OpenSSLCrypto.memory().write(inputPtr, input, offset, len);
         int result = OpenSSLCrypto.EVP_DigestUpdate(evpMdCtx, inputPtr, len);
         if (result != 1) {
            throw new ProviderException("EVP_DigestUpdate failed");
         }
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error updating digest", e);
      } finally {
         OpenSSLCrypto.free(inputPtr);
      }
   }

   @Override
   protected byte[] engineDigest() {
      int digestBuffer = 0;
      int digestLenPtr = 0;
      try {
         int digestSize = OpenSSLCrypto.EVP_MD_size(handle);
         if (digestSize <= 0) {
            throw new ProviderException("Invalid digest size: " + digestSize);
         }

         digestBuffer = OpenSSLCrypto.malloc(digestSize);
         digestLenPtr = OpenSSLCrypto.malloc(4);
         OpenSSLCrypto.memory().writeI32(digestLenPtr, digestSize);

         int tempEvpMdCtx = OpenSSLCrypto.EVP_MD_CTX_new();
         if (tempEvpMdCtx == 0) {
            throw new ProviderException("Failed to duplicate EVP_MD_CTX for finalization");
         }
         int result = OpenSSLCrypto.EVP_DigestFinal_ex(evpMdCtx, digestBuffer, digestLenPtr);
         if (result != 1) {
            throw new ProviderException("EVP_DigestFinal_ex failed");
         }
         byte[] digest = OpenSSLCrypto.memory().readBytes(digestBuffer, digestSize);
         engineReset();
         return digest;
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error calculating digest", e);
      } finally {
         OpenSSLCrypto.free(digestBuffer);
         OpenSSLCrypto.free(digestLenPtr);
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
