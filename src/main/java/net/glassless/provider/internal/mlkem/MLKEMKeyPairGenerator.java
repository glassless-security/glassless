package net.glassless.provider.internal.mlkem;

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
 * KeyPairGenerator for ML-KEM (Module-Lattice Key Encapsulation Mechanism).
 * Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 variants.
 *
 * <p>ML-KEM is standardized in FIPS 203 and requires OpenSSL 3.5+.
 */
public class MLKEMKeyPairGenerator extends KeyPairGeneratorSpi {

   private static final System.Logger LOG = GlaSSLessLog.KEY_PAIR_GEN;

   // OpenSSL algorithm names
   protected static final String MLKEM512 = "mlkem512";
   protected static final String MLKEM768 = "mlkem768";
   protected static final String MLKEM1024 = "mlkem1024";

   protected String algorithmName = MLKEM768;  // Default to ML-KEM-768
   protected String jcaAlgorithm = "ML-KEM-768";


   public MLKEMKeyPairGenerator() {
      // Default constructor
   }

   protected MLKEMKeyPairGenerator(String algorithmName, String jcaAlgorithm) {
      this.algorithmName = algorithmName;
      this.jcaAlgorithm = jcaAlgorithm;
   }

   @Override
   public void initialize(int keysize, SecureRandom random) {
      // ML-KEM uses security strength levels, not key sizes
      // Map security levels: 128 -> 512, 192 -> 768, 256 -> 1024
      switch (keysize) {
         case 128, 512 -> {
            this.algorithmName = MLKEM512;
            this.jcaAlgorithm = "ML-KEM-512";
         }
         case 192, 768 -> {
            this.algorithmName = MLKEM768;
            this.jcaAlgorithm = "ML-KEM-768";
         }
         case 256, 1024 -> {
            this.algorithmName = MLKEM1024;
            this.jcaAlgorithm = "ML-KEM-1024";
         }
         default -> throw new InvalidParameterException(
            "Invalid ML-KEM parameter. Use 512, 768, or 1024 (or security levels 128, 192, 256)");
      }
   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (params instanceof NamedParameterSpec nps) {
         String name = nps.getName().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
         switch (name) {
            case "MLKEM512" -> {
               this.algorithmName = MLKEM512;
               this.jcaAlgorithm = "ML-KEM-512";
            }
            case "MLKEM768" -> {
               this.algorithmName = MLKEM768;
               this.jcaAlgorithm = "ML-KEM-768";
            }
            case "MLKEM1024" -> {
               this.algorithmName = MLKEM1024;
               this.jcaAlgorithm = "ML-KEM-1024";
            }
            default -> throw new InvalidAlgorithmParameterException(
               "Unsupported ML-KEM variant: " + nps.getName() + ". Supported: ML-KEM-512, ML-KEM-768, ML-KEM-1024");
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
            new GlaSSLessMLKEMPublicKey(jcaAlgorithm, keys[0]),
            new GlaSSLessMLKEMPrivateKey(jcaAlgorithm, keys[1]));
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating ML-KEM key pair", e);
      }
   }
}
