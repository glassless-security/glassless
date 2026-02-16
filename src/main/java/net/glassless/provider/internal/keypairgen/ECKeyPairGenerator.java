package net.glassless.provider.internal.keypairgen;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * EC (Elliptic Curve) KeyPairGenerator using OpenSSL.
 */
public class ECKeyPairGenerator extends KeyPairGeneratorSpi {

   private static final int DEFAULT_KEY_SIZE = 256;

   private int curveNid = OpenSSLCrypto.NID_X9_62_prime256v1; // Default to P-256
   private String curveName = "secp256r1";
   private SecureRandom random;

   @Override
   public void initialize(int keysize, SecureRandom random) {
      // Map key size to curve
      switch (keysize) {
         case 256:
            this.curveNid = OpenSSLCrypto.NID_X9_62_prime256v1;
            this.curveName = "secp256r1";
            break;
         case 384:
            this.curveNid = OpenSSLCrypto.NID_secp384r1;
            this.curveName = "secp384r1";
            break;
         case 521:
            this.curveNid = OpenSSLCrypto.NID_secp521r1;
            this.curveName = "secp521r1";
            break;
         default:
            throw new InvalidParameterException("Unsupported EC key size: " + keysize + ". Supported sizes: 256, 384, 521");
      }
      this.random = random;
   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (params instanceof ECGenParameterSpec ecParams) {
         String name = ecParams.getName();

         // Map curve name to NID
         int nid = getCurveNid(name);
         if (nid == 0) {
            throw new InvalidAlgorithmParameterException("Unsupported EC curve: " + name);
         }
         this.curveNid = nid;
         this.curveName = name;
         this.random = random;
      } else if (params != null) {
         throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params.getClass().getName());
      }
   }

   private int getCurveNid(String curveName) {
      // Normalize curve name and map to NID
      String normalized = curveName.toLowerCase().replace("-", "").replace("_", "");

      // P-256 / secp256r1 / prime256v1
      switch (normalized) {
         case "secp256r1", "p256", "prime256v1", "nistp256" -> {
            return OpenSSLCrypto.NID_X9_62_prime256v1;
         }

         // P-384 / secp384r1
         case "secp384r1", "p384", "nistp384" -> {
            return OpenSSLCrypto.NID_secp384r1;
         }

         // P-521 / secp521r1
         case "secp521r1", "p521", "nistp521" -> {
            return OpenSSLCrypto.NID_secp521r1;
         }

         // secp256k1 (Bitcoin curve)
         case "secp256k1" -> {
            return OpenSSLCrypto.NID_secp256k1;
         }
      }

      // Try to look up by OpenSSL name
      try {
         int nid = OpenSSLCrypto.OBJ_sn2nid(curveName);
         if (nid != 0) {
            return nid;
         }
         // Try OID lookup
         nid = OpenSSLCrypto.OBJ_txt2nid(curveName);
         return nid;
      } catch (Throwable e) {
         return 0;
      }
   }

   @Override
   public KeyPair generateKeyPair() {
      try {
         // Create EC key generation context
         int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(0, "EC", 0);
         if (ctx == 0) {
            throw new ProviderException("Failed to create EVP_PKEY_CTX for EC");
         }

         try {
            // Initialize for key generation
            int result = OpenSSLCrypto.EVP_PKEY_keygen_init(ctx);
            if (result <= 0) {
               throw new ProviderException("EVP_PKEY_keygen_init failed");
            }

            // Set curve
            result = OpenSSLCrypto.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveNid);
            if (result <= 0) {
               throw new ProviderException("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed for curve NID " + curveNid);
            }

            // Generate the key pair
            int pkeyPtr = OpenSSLCrypto.malloc(4);
            OpenSSLCrypto.memory().writeI32(pkeyPtr, 0);
            result = OpenSSLCrypto.EVP_PKEY_keygen(ctx, pkeyPtr);
            if (result <= 0) {
               OpenSSLCrypto.free(pkeyPtr);
               throw new ProviderException("EVP_PKEY_keygen failed");
            }

            int pkey = OpenSSLCrypto.memory().readInt(pkeyPtr);
            OpenSSLCrypto.free(pkeyPtr);
            if (pkey == 0) {
               throw new ProviderException("Generated key is null");
            }

            try {
               // Export private key to DER format (PKCS#8)
               byte[] privateKeyBytes = OpenSSLCrypto.exportPrivateKey(pkey);
               PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

               // Export public key to DER format (SubjectPublicKeyInfo / X.509)
               byte[] publicKeyBytes = OpenSSLCrypto.exportPublicKey(pkey);
               X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

               // Use standard KeyFactory to create the key objects
               KeyFactory keyFactory = KeyFactory.getInstance("EC");
               PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
               PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

               return new KeyPair(publicKey, privateKey);

            } finally {
               OpenSSLCrypto.EVP_PKEY_free(pkey);
            }

         } finally {
            OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
         }

      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating EC key pair", e);
      }
   }
}
