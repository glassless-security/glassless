package net.glassless.provider.internal.mlkem;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;

import net.glassless.provider.internal.GlaSSLessLog;
import net.glassless.provider.internal.KEMUtils;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Base KEMSpi implementation for ML-KEM.
 * Implements the Key Encapsulation Mechanism as defined in FIPS 203.
 */
public class MLKEM implements KEMSpi {

   private static final System.Logger LOG = GlaSSLessLog.KEM;

   protected final String opensslName;
   protected final String jcaAlgorithm;
   protected final int sharedSecretSize;

   public MLKEM() {
      this("mlkem768", "ML-KEM-768", 32);
   }

   protected MLKEM(String opensslName, String jcaAlgorithm, int sharedSecretSize) {
      this.opensslName = opensslName;
      this.jcaAlgorithm = jcaAlgorithm;
      this.sharedSecretSize = sharedSecretSize;
   }

   @Override
   public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                                                SecureRandom secureRandom)
      throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (publicKey == null) {
         throw new InvalidKeyException("Public key cannot be null");
      }
      if (spec != null) {
         throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not supported for ML-KEM");
      }

      byte[] encodedKey = publicKey.getEncoded();
      if (encodedKey == null) {
         throw new InvalidKeyException("Public key encoding is null");
      }

      LOG.log(System.Logger.Level.DEBUG, "newEncapsulator: {0}", jcaAlgorithm);
      return new MLKEMEncapsulator(encodedKey, sharedSecretSize);
   }

   @Override
   public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
      throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (privateKey == null) {
         throw new InvalidKeyException("Private key cannot be null");
      }
      if (spec != null) {
         throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not supported for ML-KEM");
      }

      byte[] encodedKey = privateKey.getEncoded();
      if (encodedKey == null) {
         throw new InvalidKeyException("Private key encoding is null");
      }

      LOG.log(System.Logger.Level.DEBUG, "newDecapsulator: {0}", jcaAlgorithm);
      return new MLKEMDecapsulator(encodedKey, sharedSecretSize);
   }

   private static class MLKEMEncapsulator implements EncapsulatorSpi {
      private final byte[] publicKeyEncoded;
      private final int sharedSecretSize;
      private int encapsulationSize = -1;

      MLKEMEncapsulator(byte[] publicKeyEncoded, int sharedSecretSize) {
         this.publicKeyEncoded = publicKeyEncoded;
         this.sharedSecretSize = sharedSecretSize;
      }

      @Override
      public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
         try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded, arena);
            if (pkey.equals(MemorySegment.NULL)) {
               throw new ProviderException("Failed to load public key");
            }
            try {
               KEMUtils.EncapsulateResult result = KEMUtils.encapsulate(pkey, from, to, algorithm, sharedSecretSize, arena);
               encapsulationSize = result.encapsulationSize();
               return result.encapsulated();
            } finally {
               OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
         } catch (ProviderException e) {
            throw e;
         } catch (Throwable e) {
            throw new ProviderException("ML-KEM encapsulation failed", e);
         }
      }

      @Override
      public int engineSecretSize() {
         return sharedSecretSize;
      }

      @Override
      public int engineEncapsulationSize() {
         if (encapsulationSize < 0) {
            try (Arena arena = Arena.ofConfined()) {
               MemorySegment pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded, arena);
               if (!pkey.equals(MemorySegment.NULL)) {
                  try {
                     encapsulationSize = KEMUtils.queryEncapsulationSize(pkey, arena);
                  } finally {
                     OpenSSLCrypto.EVP_PKEY_free(pkey);
                  }
               }
            } catch (Throwable e) {
               // Ignore
            }
         }
         return Math.max(encapsulationSize, 0);
      }
   }

   private static class MLKEMDecapsulator implements DecapsulatorSpi {
      private final byte[] privateKeyEncoded;
      private final int sharedSecretSize;
      private final int encapsulationSize;

      MLKEMDecapsulator(byte[] privateKeyEncoded, int sharedSecretSize) {
         this.privateKeyEncoded = privateKeyEncoded;
         this.sharedSecretSize = sharedSecretSize;
         this.encapsulationSize = queryEncapsulationSize();
      }

      @Override
      public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
         throws DecapsulateException {
         try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, privateKeyEncoded, arena);
            if (pkey.equals(MemorySegment.NULL)) {
               throw new DecapsulateException("Failed to load private key");
            }
            try {
               return KEMUtils.decapsulate(pkey, encapsulation, from, to, algorithm, sharedSecretSize, arena);
            } finally {
               OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
         } catch (DecapsulateException e) {
            throw e;
         } catch (Throwable e) {
            throw new DecapsulateException("ML-KEM decapsulation failed", e);
         }
      }

      @Override
      public int engineSecretSize() {
         return sharedSecretSize;
      }

      @Override
      public int engineEncapsulationSize() {
         return encapsulationSize;
      }

      private int queryEncapsulationSize() {
         try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, privateKeyEncoded, arena);
            if (!pkey.equals(MemorySegment.NULL)) {
               try {
                  int size = KEMUtils.queryEncapsulationSize(pkey, arena);
                  if (size > 0) {
                     return size;
                  }
               } finally {
                  OpenSSLCrypto.EVP_PKEY_free(pkey);
               }
            }
         } catch (Throwable e) {
            // Ignore
         }
         return 0;
      }
   }
}
