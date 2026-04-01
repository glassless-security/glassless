package net.glassless.provider.internal.xdh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Locale;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyPairGenerator for XDH (X25519 and X448).
 */
public class XDHKeyPairGenerator extends KeyPairGeneratorSpi {

   private NamedParameterSpec params = NamedParameterSpec.X25519;  // Default to X25519


   @Override
   public void initialize(int keysize, SecureRandom random) {
      // XDH doesn't use key size, use algorithm-based initialization
      if (keysize == 255 || keysize == 256) {
         this.params = NamedParameterSpec.X25519;
      } else if (keysize == 448 || keysize == 456) {
         this.params = NamedParameterSpec.X448;
      } else {
         throw new InvalidParameterException(
            "XDH key size must be 255/256 (X25519) or 448/456 (X448), got: " + keysize);
      }
   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (params instanceof NamedParameterSpec nps) {
         String name = nps.getName();
         if ("X25519".equalsIgnoreCase(name)) {
            this.params = NamedParameterSpec.X25519;
         } else if ("X448".equalsIgnoreCase(name)) {
            this.params = NamedParameterSpec.X448;
         } else {
            throw new InvalidAlgorithmParameterException(
               "Unsupported XDH curve: " + name + ". Supported: X25519, X448");
         }
      } else {
         throw new InvalidAlgorithmParameterException(
            "NamedParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }
   }

   @Override
   public KeyPair generateKeyPair() {
      String algorithmName = params.getName().toUpperCase(Locale.ROOT);  // X25519 or X448

      try {
         byte[][] keys = OpenSSLCrypto.generateKeyPair(algorithmName, null);

         // Extract raw key bytes
         int keyLen = algorithmName.equals("X25519") ? 32 : 56;
         byte[] rawPublicKey = extractRawPublicKey(keys[0], keyLen);
         byte[] rawPrivateKey = extractRawPrivateKey(keys[1], keyLen);

         // Create u-coordinate from raw public key (little-endian)
         BigInteger u = createUCoordinate(rawPublicKey);

         return new KeyPair(
            new GlaSSLessXECPublicKey(params, u, keys[0]),
            new GlaSSLessXECPrivateKey(params, rawPrivateKey, keys[1]));
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating XDH key pair", e);
      }
   }

   /**
    * Extracts the raw public key bytes from X.509 encoded key.
    */
   private byte[] extractRawPublicKey(byte[] encoded, int keyLen) {
      byte[] raw = new byte[keyLen];
      System.arraycopy(encoded, encoded.length - keyLen, raw, 0, keyLen);
      return raw;
   }

   /**
    * Extracts the raw private key bytes from PKCS#8 encoded key.
    */
   private byte[] extractRawPrivateKey(byte[] encoded, int keyLen) {
      byte[] raw = new byte[keyLen];
      System.arraycopy(encoded, encoded.length - keyLen, raw, 0, keyLen);
      return raw;
   }

   /**
    * Creates a BigInteger u-coordinate from raw public key bytes (little-endian).
    */
   private BigInteger createUCoordinate(byte[] raw) {
      // XDH uses little-endian encoding, reverse for BigInteger
      byte[] reversed = new byte[raw.length + 1];  // +1 for sign byte
      reversed[0] = 0;  // Ensure positive
      for (int i = 0; i < raw.length; i++) {
         reversed[i + 1] = raw[raw.length - 1 - i];
      }
      return new BigInteger(reversed);
   }
}
