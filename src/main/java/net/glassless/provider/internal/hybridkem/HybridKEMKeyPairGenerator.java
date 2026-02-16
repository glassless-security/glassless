package net.glassless.provider.internal.hybridkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * KeyPairGenerator for hybrid KEM algorithms.
 * Supports X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, and SecP384r1MLKEM1024.
 *
 * <p>Hybrid KEMs combine classical key agreement with post-quantum ML-KEM
 * for quantum-resistant key encapsulation. Requires OpenSSL 3.5+.
 */
public class HybridKEMKeyPairGenerator extends KeyPairGeneratorSpi {

   // OpenSSL algorithm names
   protected static final String X25519_MLKEM768 = "X25519MLKEM768";
   protected static final String X448_MLKEM1024 = "X448MLKEM1024";
   protected static final String SECP256R1_MLKEM768 = "SecP256r1MLKEM768";
   protected static final String SECP384R1_MLKEM1024 = "SecP384r1MLKEM1024";

   protected String algorithmName = X25519_MLKEM768;  // Default
   protected String jcaAlgorithm = "X25519MLKEM768";
   protected SecureRandom random;

   public HybridKEMKeyPairGenerator() {
      // Default constructor
   }

   protected HybridKEMKeyPairGenerator(String algorithmName, String jcaAlgorithm) {
      this.algorithmName = algorithmName;
      this.jcaAlgorithm = jcaAlgorithm;
   }

   @Override
   public void initialize(int keysize, SecureRandom random) {
      // Keysize is not meaningful for hybrid KEMs, use NamedParameterSpec instead
      throw new InvalidParameterException(
         "Hybrid KEMs do not use key size. Use initialize(AlgorithmParameterSpec, SecureRandom) with " +
         "NamedParameterSpec(\"X25519MLKEM768\") or similar.");
   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
         throws InvalidAlgorithmParameterException {
      if (params instanceof NamedParameterSpec nps) {
         String name = normalizeAlgorithmName(nps.getName());
         switch (name) {
            case "X25519MLKEM768" -> {
               this.algorithmName = X25519_MLKEM768;
               this.jcaAlgorithm = "X25519MLKEM768";
            }
            case "X448MLKEM1024" -> {
               this.algorithmName = X448_MLKEM1024;
               this.jcaAlgorithm = "X448MLKEM1024";
            }
            case "SECP256R1MLKEM768", "P256MLKEM768" -> {
               this.algorithmName = SECP256R1_MLKEM768;
               this.jcaAlgorithm = "SecP256r1MLKEM768";
            }
            case "SECP384R1MLKEM1024", "P384MLKEM1024" -> {
               this.algorithmName = SECP384R1_MLKEM1024;
               this.jcaAlgorithm = "SecP384r1MLKEM1024";
            }
            default -> throw new InvalidAlgorithmParameterException(
               "Unsupported hybrid KEM variant: " + nps.getName() +
               ". Supported: X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, SecP384r1MLKEM1024");
         }
      } else if (params != null) {
         throw new InvalidAlgorithmParameterException(
            "NamedParameterSpec required, got: " + params.getClass().getName());
      }
      this.random = random;
   }

   private static String normalizeAlgorithmName(String name) {
      return name.toUpperCase()
         .replace("-", "")
         .replace("_", "")
         .replace("ECDHX", "X")  // Handle ECDH prefix
         .replace("ECDH", "");   // Remove ECDH prefix
   }

   @Override
   public KeyPair generateKeyPair() {
      try {
         // Create EVP_PKEY_CTX for hybrid KEM key generation
         int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
            0,
            algorithmName,
            0
         );
         if (ctx == 0) {
            throw new ProviderException("Failed to create EVP_PKEY_CTX for " + algorithmName +
               ". Hybrid KEMs require OpenSSL 3.5+");
         }

         try {
            // Initialize for key generation
            int result = OpenSSLCrypto.EVP_PKEY_keygen_init(ctx);
            if (result != 1) {
               throw new ProviderException("EVP_PKEY_keygen_init failed for " + algorithmName);
            }

            // Generate the key pair
            int pkeyPtr = OpenSSLCrypto.malloc(4);
            try {
               OpenSSLCrypto.memory().writeI32(pkeyPtr, 0);
               result = OpenSSLCrypto.EVP_PKEY_keygen(ctx, pkeyPtr);
               if (result != 1) {
                  throw new ProviderException("EVP_PKEY_keygen failed for " + algorithmName);
               }

               int pkey = OpenSSLCrypto.memory().readInt(pkeyPtr);
               if (pkey == 0) {
                  throw new ProviderException("Generated key is null");
               }

               try {
                  // Export keys in raw format (hybrid KEMs don't have standard ASN.1 encoders)
                  byte[] rawPublicKey = OpenSSLCrypto.exportRawPublicKey(pkey);
                  byte[] rawPrivateKey = OpenSSLCrypto.exportRawPrivateKey(pkey);

                  // Create key objects with raw key bytes
                  GlaSSLessHybridKEMPublicKey publicKey = new GlaSSLessHybridKEMPublicKey(
                     jcaAlgorithm, algorithmName, rawPublicKey);
                  GlaSSLessHybridKEMPrivateKey privateKey = new GlaSSLessHybridKEMPrivateKey(
                     jcaAlgorithm, algorithmName, rawPrivateKey);

                  return new KeyPair(publicKey, privateKey);
               } finally {
                  OpenSSLCrypto.EVP_PKEY_free(pkey);
               }
            } finally {
               OpenSSLCrypto.free(pkeyPtr);
            }
         } finally {
            OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
         }
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating hybrid KEM key pair", e);
      }
   }
}
