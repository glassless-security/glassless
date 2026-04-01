package net.glassless.provider.internal.cipher;

import java.security.InvalidKeyException;
import java.security.Key;

/**
 * Generic ARIA cipher that determines the OpenSSL algorithm name from the key size
 * at init time. This allows using standard JCA names like "ARIA/GCM/NoPadding"
 * without specifying the key size upfront.
 */
public class ARIACipher extends AbstractCipher {

   private final String opensslModeName;

   protected ARIACipher(String opensslModeName, CipherMode mode, CipherPadding padding) {
      super(null, mode, padding);
      this.opensslModeName = opensslModeName;
   }

   @Override
   protected void resolveAlgorithm(Key key) throws InvalidKeyException {
      if (key == null) {
         throw new InvalidKeyException("Key must not be null");
      }
      byte[] encoded = key.getEncoded();
      if (encoded == null) {
         throw new InvalidKeyException("Key encoding must not be null");
      }
      int keySizeBits = encoded.length * 8;
      String keySize = switch (keySizeBits) {
         case 128 -> "128";
         case 192 -> "192";
         case 256 -> "256";
         default -> throw new InvalidKeyException(
            "Unsupported ARIA key size: " + keySizeBits + " bits. Supported: 128, 192, 256");
      };
      setAlgorithmName("aria-" + keySize + "-" + opensslModeName);
   }

   public static class CbcNoPadding extends ARIACipher {
      public CbcNoPadding() { super("cbc", CipherMode.CBC, CipherPadding.NOPADDING); }
   }

   public static class CbcPKCS5Padding extends ARIACipher {
      public CbcPKCS5Padding() { super("cbc", CipherMode.CBC, CipherPadding.PKCS5PADDING); }
   }

   public static class EcbNoPadding extends ARIACipher {
      public EcbNoPadding() { super("ecb", CipherMode.ECB, CipherPadding.NOPADDING); }
   }

   public static class EcbPKCS5Padding extends ARIACipher {
      public EcbPKCS5Padding() { super("ecb", CipherMode.ECB, CipherPadding.PKCS5PADDING); }
   }

   public static class CtrNoPadding extends ARIACipher {
      public CtrNoPadding() { super("ctr", CipherMode.CTR, CipherPadding.NOPADDING); }
   }

   public static class CtrPKCS5Padding extends ARIACipher {
      public CtrPKCS5Padding() { super("ctr", CipherMode.CTR, CipherPadding.PKCS5PADDING); }
   }

   public static class CfbNoPadding extends ARIACipher {
      public CfbNoPadding() { super("cfb", CipherMode.CFB, CipherPadding.NOPADDING); }
   }

   public static class CfbPKCS5Padding extends ARIACipher {
      public CfbPKCS5Padding() { super("cfb", CipherMode.CFB, CipherPadding.PKCS5PADDING); }
   }

   public static class OfbNoPadding extends ARIACipher {
      public OfbNoPadding() { super("ofb", CipherMode.OFB, CipherPadding.NOPADDING); }
   }

   public static class OfbPKCS5Padding extends ARIACipher {
      public OfbPKCS5Padding() { super("ofb", CipherMode.OFB, CipherPadding.PKCS5PADDING); }
   }

   public static class GcmNoPadding extends ARIACipher {
      public GcmNoPadding() { super("gcm", CipherMode.GCM, CipherPadding.NOPADDING); }
   }
}
