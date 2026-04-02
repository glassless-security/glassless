package net.glassless.provider.internal.keypairgen;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Locale;

import net.glassless.provider.internal.OpenSSLCrypto;
import net.glassless.provider.internal.keyfactory.GlaSSLessECPrivateKey;
import net.glassless.provider.internal.keyfactory.GlaSSLessECPublicKey;

/**
 * EC (Elliptic Curve) KeyPairGenerator using OpenSSL.
 */
public class ECKeyPairGenerator extends KeyPairGeneratorSpi {

   private static final int DEFAULT_KEY_SIZE = 256;

   private int curveNid = OpenSSLCrypto.NID_X9_62_prime256v1; // Default to P-256
   private ECParameterSpec cachedParams; // Cached curve parameters for current NID

   @Override
   public void initialize(int keysize, SecureRandom random) {
      // Map key size to curve
      int newNid = switch (keysize) {
         case 256 -> OpenSSLCrypto.NID_X9_62_prime256v1;
         case 384 -> OpenSSLCrypto.NID_secp384r1;
         case 521 -> OpenSSLCrypto.NID_secp521r1;
         default -> throw new InvalidParameterException("Unsupported EC key size: " + keysize + ". Supported sizes: 256, 384, 521");
      };
      if (newNid != this.curveNid) {
         this.cachedParams = null;
      }
      this.curveNid = newNid;
   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      int newNid;
      if (params instanceof ECGenParameterSpec ecParams) {
         String name = ecParams.getName();
         newNid = getCurveNid(name);
         if (newNid == 0) {
            throw new InvalidAlgorithmParameterException("Unsupported EC curve: " + name);
         }
      } else if (params instanceof ECParameterSpec ecSpec) {
         // Handle ECParameterSpec (including sun.security.util.NamedCurve used by JSSE)
         int fieldSize = ecSpec.getCurve().getField().getFieldSize();
         newNid = switch (fieldSize) {
            case 256 -> OpenSSLCrypto.NID_X9_62_prime256v1;
            case 384 -> OpenSSLCrypto.NID_secp384r1;
            case 521 -> OpenSSLCrypto.NID_secp521r1;
            default -> throw new InvalidAlgorithmParameterException(
               "Unsupported EC field size: " + fieldSize);
         };
      } else if (params != null) {
         throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params.getClass().getName());
      } else {
         return;
      }
      if (newNid != this.curveNid) {
         this.cachedParams = null;
      }
      this.curveNid = newNid;
   }

   private int getCurveNid(String curveName) {
      // Normalize curve name and map to NID
      String normalized = curveName.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");

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
      try (Arena arena = Arena.ofConfined()) {
         // Generate key pair using OpenSSL
         MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(
            MemorySegment.NULL, "EC", MemorySegment.NULL, arena);
         if (ctx.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to create EVP_PKEY_CTX for EC");
         }
         try {
            int r = OpenSSLCrypto.EVP_PKEY_keygen_init(ctx);
            if (r <= 0) {
               throw new ProviderException("EVP_PKEY_keygen_init failed");
            }
            r = OpenSSLCrypto.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveNid);
            if (r <= 0) {
               throw new ProviderException("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed for curve NID " + curveNid);
            }
            MemorySegment pkeyPtr = arena.allocate(ValueLayout.ADDRESS);
            r = OpenSSLCrypto.EVP_PKEY_keygen(ctx, pkeyPtr);
            if (r <= 0) {
               throw new ProviderException("EVP_PKEY_keygen failed");
            }
            MemorySegment pkey = pkeyPtr.get(ValueLayout.ADDRESS, 0);
            try {
               // Cache curve parameters — they are identical for every key on the same curve
               if (cachedParams == null) {
                  cachedParams = OpenSSLCrypto.extractECParameterSpec(pkey, arena);
               }
               ECParameterSpec params = cachedParams;
               ECPoint w = OpenSSLCrypto.extractECPublicPoint(pkey, arena);
               java.math.BigInteger s = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "priv", arena);

               byte[] publicEncoded = OpenSSLCrypto.exportPublicKey(pkey, arena);
               byte[] privateEncoded = OpenSSLCrypto.exportPrivateKey(pkey, arena);

               return new KeyPair(
                  new GlaSSLessECPublicKey(w, params, publicEncoded),
                  new GlaSSLessECPrivateKey(s, params, privateEncoded));
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
