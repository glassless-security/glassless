package net.glassless.provider.internal.keypairgen;

import java.lang.foreign.Arena;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
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

   @Override
   public void initialize(int keysize, SecureRandom random) {
      // Map key size to curve
      switch (keysize) {
         case 256:
            this.curveNid = OpenSSLCrypto.NID_X9_62_prime256v1;
            break;
         case 384:
            this.curveNid = OpenSSLCrypto.NID_secp384r1;
            break;
         case 521:
            this.curveNid = OpenSSLCrypto.NID_secp521r1;
            break;
         default:
            throw new InvalidParameterException("Unsupported EC key size: " + keysize + ". Supported sizes: 256, 384, 521");
      }

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
      try (Arena arena = Arena.ofConfined()) {
         int nid = OpenSSLCrypto.OBJ_sn2nid(curveName, arena);
         if (nid != 0) {
            return nid;
         }
         // Try OID lookup
         nid = OpenSSLCrypto.OBJ_txt2nid(curveName, arena);
         return nid;
      } catch (Throwable e) {
         return 0;
      }
   }

   @Override
   public KeyPair generateKeyPair() {
      try {
         byte[][] keys = OpenSSLCrypto.generateKeyPair("EC",
            ctx -> {
               int r = OpenSSLCrypto.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveNid);
               if (r <= 0) {
                  throw new ProviderException("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed for curve NID " + curveNid);
               }
            });
         KeyFactory keyFactory = KeyFactory.getInstance("EC");
         return new KeyPair(
            keyFactory.generatePublic(new X509EncodedKeySpec(keys[0])),
            keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keys[1])));
      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating EC key pair", e);
      }
   }
}
