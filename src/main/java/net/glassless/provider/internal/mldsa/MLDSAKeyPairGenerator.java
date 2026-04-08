package net.glassless.provider.internal.mldsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Locale;

import net.glassless.provider.internal.GlaSSLessLog;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyPairGenerator for ML-DSA (Module-Lattice Digital Signature Algorithm).
 * Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 variants.
 *
 * <p>ML-DSA is standardized in FIPS 204 and requires OpenSSL 3.5+.
 */
public class MLDSAKeyPairGenerator extends KeyPairGeneratorSpi {

   private static final System.Logger LOG = GlaSSLessLog.KEY_PAIR_GEN;

   // OpenSSL algorithm names
   protected static final String MLDSA44 = "mldsa44";
   protected static final String MLDSA65 = "mldsa65";
   protected static final String MLDSA87 = "mldsa87";

   protected String algorithmName = MLDSA65;  // Default to ML-DSA-65
   protected String jcaAlgorithm = "ML-DSA-65";


   public MLDSAKeyPairGenerator() {
      // Default constructor
   }

   protected MLDSAKeyPairGenerator(String algorithmName, String jcaAlgorithm) {
      this.algorithmName = algorithmName;
      this.jcaAlgorithm = jcaAlgorithm;
   }

   @Override
   public void initialize(int keysize, SecureRandom random) {
      // ML-DSA uses security category levels
      // Map: 44 -> Category 2, 65 -> Category 3, 87 -> Category 5
      switch (keysize) {
         case 44, 128 -> {
            this.algorithmName = MLDSA44;
            this.jcaAlgorithm = "ML-DSA-44";
         }
         case 65, 192 -> {
            this.algorithmName = MLDSA65;
            this.jcaAlgorithm = "ML-DSA-65";
         }
         case 87, 256 -> {
            this.algorithmName = MLDSA87;
            this.jcaAlgorithm = "ML-DSA-87";
         }
         default -> throw new InvalidParameterException(
            "Invalid ML-DSA parameter. Use 44, 65, or 87 (or security levels 128, 192, 256)");
      }
   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (params instanceof NamedParameterSpec nps) {
         String name = nps.getName().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
         switch (name) {
            case "MLDSA44" -> {
               this.algorithmName = MLDSA44;
               this.jcaAlgorithm = "ML-DSA-44";
            }
            case "MLDSA65" -> {
               this.algorithmName = MLDSA65;
               this.jcaAlgorithm = "ML-DSA-65";
            }
            case "MLDSA87" -> {
               this.algorithmName = MLDSA87;
               this.jcaAlgorithm = "ML-DSA-87";
            }
            default -> throw new InvalidAlgorithmParameterException(
               "Unsupported ML-DSA variant: " + nps.getName() + ". Supported: ML-DSA-44, ML-DSA-65, ML-DSA-87");
         }
      } else {
         throw new InvalidAlgorithmParameterException(
            "NamedParameterSpec required, got: " + (params == null ? "null" : params.getClass().getName()));
      }
   }

   @Override
   public KeyPair generateKeyPair() {
      try {
         byte[][] keys = OpenSSLCrypto.generateKeyPair(algorithmName, null);
         LOG.log(System.Logger.Level.DEBUG, "{0}", jcaAlgorithm);
         return new KeyPair(
            new GlaSSLessMLDSAPublicKey(jcaAlgorithm, keys[0]),
            new GlaSSLessMLDSAPrivateKey(jcaAlgorithm, keys[1]));
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating ML-DSA key pair", e);
      }
   }
}
