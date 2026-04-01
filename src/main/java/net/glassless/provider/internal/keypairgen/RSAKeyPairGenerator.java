package net.glassless.provider.internal.keypairgen;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

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
      try {
         byte[][] keys = OpenSSLCrypto.generateKeyPair("RSA",
            ctx -> {
               int r = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize);
               if (r <= 0) {
                  throw new ProviderException("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
               }
            });
         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
         return new KeyPair(
            keyFactory.generatePublic(new X509EncodedKeySpec(keys[0])),
            keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keys[1])));
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating RSA key pair", e);
      }
   }
}
