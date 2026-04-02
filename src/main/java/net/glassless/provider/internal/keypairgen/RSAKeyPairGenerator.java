package net.glassless.provider.internal.keypairgen;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;
import net.glassless.provider.internal.keyfactory.GlaSSLessRSAPublicKey;
import net.glassless.provider.internal.keyfactory.RSAKeyFactory;

/**
 * RSA KeyPairGenerator using OpenSSL.
 */
public class RSAKeyPairGenerator extends KeyPairGeneratorSpi {

   private static final int DEFAULT_KEY_SIZE = 2048;
   private static final int MIN_KEY_SIZE = 512;
   private static final int MAX_KEY_SIZE = 16384;

   private int keySize = DEFAULT_KEY_SIZE;


   @Override
   public void initialize(int keysize, SecureRandom random) {
      if (keysize < MIN_KEY_SIZE || keysize > MAX_KEY_SIZE) {
         throw new InvalidParameterException("Key size must be between " + MIN_KEY_SIZE + " and " + MAX_KEY_SIZE + " bits");
      }
      this.keySize = keysize;

   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (params instanceof RSAKeyGenParameterSpec rsaParams) {
         int keysize = rsaParams.getKeysize();
         if (keysize < MIN_KEY_SIZE || keysize > MAX_KEY_SIZE) {
            throw new InvalidAlgorithmParameterException("Key size must be between " + MIN_KEY_SIZE + " and " + MAX_KEY_SIZE + " bits");
         }
         this.keySize = keysize;

      } else if (params != null) {
         throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params.getClass().getName());
      }
   }

   @Override
   public KeyPair generateKeyPair() {
      try (Arena arena = Arena.ofConfined()) {
         byte[][] keys = OpenSSLCrypto.generateKeyPair("RSA",
            ctx -> {
               int r = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize);
               if (r <= 0) {
                  throw new ProviderException("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
               }
            });

         // Parse the generated keys using OpenSSL to extract components
         byte[] pubEncoded = keys[0];
         byte[] privEncoded = keys[1];

         // Extract public key components
         MemorySegment pubPkey = OpenSSLCrypto.loadPublicKey(pubEncoded, arena);
         if (pubPkey.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to parse generated RSA public key");
         }
         java.math.BigInteger n, e;
         try {
            n = OpenSSLCrypto.EVP_PKEY_get_bn_param(pubPkey, "n", arena);
            e = OpenSSLCrypto.EVP_PKEY_get_bn_param(pubPkey, "e", arena);
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(pubPkey);
         }

         // Extract private key components (including CRT params)
         MemorySegment privPkey = OpenSSLCrypto.loadPrivateKey(0, privEncoded, arena);
         if (privPkey.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to parse generated RSA private key");
         }
         try {
            return new KeyPair(
               new GlaSSLessRSAPublicKey(n, e, pubEncoded),
               RSAKeyFactory.extractRSAPrivateKey(privPkey, arena, privEncoded));
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(privPkey);
         }
      } catch (ProviderException ex) {
         throw ex;
      } catch (Throwable ex) {
         throw new ProviderException("Error generating RSA key pair", ex);
      }
   }
}
