package net.glassless.provider.internal.slhdsa;

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
 * KeyPairGenerator for SLH-DSA (Stateless Hash-Based Digital Signature Algorithm).
 * Supports 12 variants based on hash (SHA2/SHAKE), security level (128/192/256),
 * and speed/size tradeoff (s/f).
 *
 * <p>SLH-DSA is standardized in FIPS 205 and requires OpenSSL 3.5+.
 */
public class SLHDSAKeyPairGenerator extends KeyPairGeneratorSpi {

   // OpenSSL algorithm names (using hyphenated format for OpenSSL 3.5+)
   public static final String SHA2_128S = "SLH-DSA-SHA2-128s";
   public static final String SHA2_128F = "SLH-DSA-SHA2-128f";
   public static final String SHA2_192S = "SLH-DSA-SHA2-192s";
   public static final String SHA2_192F = "SLH-DSA-SHA2-192f";
   public static final String SHA2_256S = "SLH-DSA-SHA2-256s";
   public static final String SHA2_256F = "SLH-DSA-SHA2-256f";
   public static final String SHAKE_128S = "SLH-DSA-SHAKE-128s";
   public static final String SHAKE_128F = "SLH-DSA-SHAKE-128f";
   public static final String SHAKE_192S = "SLH-DSA-SHAKE-192s";
   public static final String SHAKE_192F = "SLH-DSA-SHAKE-192f";
   public static final String SHAKE_256S = "SLH-DSA-SHAKE-256s";
   public static final String SHAKE_256F = "SLH-DSA-SHAKE-256f";

   protected String algorithmName = SHA2_128F;  // Default
   protected String jcaAlgorithm = "SLH-DSA-SHA2-128f";


   public SLHDSAKeyPairGenerator() {
      // Default constructor
   }

   protected SLHDSAKeyPairGenerator(String algorithmName, String jcaAlgorithm) {
      this.algorithmName = algorithmName;
      this.jcaAlgorithm = jcaAlgorithm;
   }

   @Override
   public void initialize(int keysize, SecureRandom random) {
      // Map security levels to default variants (using SHA2 and 'f' for faster signing)
      switch (keysize) {
         case 128 -> {
            this.algorithmName = SHA2_128F;
            this.jcaAlgorithm = "SLH-DSA-SHA2-128f";
         }
         case 192 -> {
            this.algorithmName = SHA2_192F;
            this.jcaAlgorithm = "SLH-DSA-SHA2-192f";
         }
         case 256 -> {
            this.algorithmName = SHA2_256F;
            this.jcaAlgorithm = "SLH-DSA-SHA2-256f";
         }
         default -> throw new InvalidParameterException(
            "Invalid SLH-DSA security level. Use 128, 192, or 256");
      }
   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (params instanceof NamedParameterSpec nps) {
         String name = normalizeAlgorithmName(nps.getName());
         setAlgorithm(name);
      } else {
         throw new InvalidAlgorithmParameterException(
            "NamedParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }
   }

   protected void setAlgorithm(String normalizedName) throws InvalidAlgorithmParameterException {
      switch (normalizedName) {
         case "SLHDSASHA2128S" -> {
            this.algorithmName = SHA2_128S;
            this.jcaAlgorithm = "SLH-DSA-SHA2-128s";
         }
         case "SLHDSASHA2128F" -> {
            this.algorithmName = SHA2_128F;
            this.jcaAlgorithm = "SLH-DSA-SHA2-128f";
         }
         case "SLHDSASHA2192S" -> {
            this.algorithmName = SHA2_192S;
            this.jcaAlgorithm = "SLH-DSA-SHA2-192s";
         }
         case "SLHDSASHA2192F" -> {
            this.algorithmName = SHA2_192F;
            this.jcaAlgorithm = "SLH-DSA-SHA2-192f";
         }
         case "SLHDSASHA2256S" -> {
            this.algorithmName = SHA2_256S;
            this.jcaAlgorithm = "SLH-DSA-SHA2-256s";
         }
         case "SLHDSASHA2256F" -> {
            this.algorithmName = SHA2_256F;
            this.jcaAlgorithm = "SLH-DSA-SHA2-256f";
         }
         case "SLHDSASHAKE128S" -> {
            this.algorithmName = SHAKE_128S;
            this.jcaAlgorithm = "SLH-DSA-SHAKE-128s";
         }
         case "SLHDSASHAKE128F" -> {
            this.algorithmName = SHAKE_128F;
            this.jcaAlgorithm = "SLH-DSA-SHAKE-128f";
         }
         case "SLHDSASHAKE192S" -> {
            this.algorithmName = SHAKE_192S;
            this.jcaAlgorithm = "SLH-DSA-SHAKE-192s";
         }
         case "SLHDSASHAKE192F" -> {
            this.algorithmName = SHAKE_192F;
            this.jcaAlgorithm = "SLH-DSA-SHAKE-192f";
         }
         case "SLHDSASHAKE256S" -> {
            this.algorithmName = SHAKE_256S;
            this.jcaAlgorithm = "SLH-DSA-SHAKE-256s";
         }
         case "SLHDSASHAKE256F" -> {
            this.algorithmName = SHAKE_256F;
            this.jcaAlgorithm = "SLH-DSA-SHAKE-256f";
         }
         default -> throw new InvalidAlgorithmParameterException(
            "Unsupported SLH-DSA variant: " + normalizedName);
      }
   }

   private String normalizeAlgorithmName(String name) {
      return name.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
   }

   @Override
   public KeyPair generateKeyPair() {
      try {
         byte[][] keys = OpenSSLCrypto.generateKeyPair(algorithmName, null);
         return new KeyPair(
            new GlaSSLessSLHDSAPublicKey(jcaAlgorithm, keys[0]),
            new GlaSSLessSLHDSAPrivateKey(jcaAlgorithm, keys[1]));
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating SLH-DSA key pair", e);
      }
   }
}
