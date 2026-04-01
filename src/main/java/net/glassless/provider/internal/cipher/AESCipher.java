package net.glassless.provider.internal.cipher;

import java.security.InvalidKeyException;
import java.security.Key;

/**
 * Generic AES cipher that determines the OpenSSL algorithm name from the key size
 * at init time. This allows using standard JCA names like "AES/GCM/NoPadding"
 * without specifying the key size upfront.
 */
public class AESCipher extends AbstractCipher {

   private final String opensslModeName;

   protected AESCipher(String opensslModeName, CipherMode mode, CipherPadding padding) {
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
            "Unsupported AES key size: " + keySizeBits + " bits. Supported: 128, 192, 256");
      };
      setAlgorithmName("aes-" + keySize + "-" + opensslModeName);
   }

   // Generic AES cipher classes for each mode/padding combination

   public static class CbcNoPadding extends AESCipher {
      public CbcNoPadding() { super("cbc", CipherMode.CBC, CipherPadding.NOPADDING); }
   }

   public static class CbcPKCS5Padding extends AESCipher {
      public CbcPKCS5Padding() { super("cbc", CipherMode.CBC, CipherPadding.PKCS5PADDING); }
   }

   public static class EcbNoPadding extends AESCipher {
      public EcbNoPadding() { super("ecb", CipherMode.ECB, CipherPadding.NOPADDING); }
   }

   public static class EcbPKCS5Padding extends AESCipher {
      public EcbPKCS5Padding() { super("ecb", CipherMode.ECB, CipherPadding.PKCS5PADDING); }
   }

   public static class CtrNoPadding extends AESCipher {
      public CtrNoPadding() { super("ctr", CipherMode.CTR, CipherPadding.NOPADDING); }
   }

   public static class CtrPKCS5Padding extends AESCipher {
      public CtrPKCS5Padding() { super("ctr", CipherMode.CTR, CipherPadding.PKCS5PADDING); }
   }

   public static class CfbNoPadding extends AESCipher {
      public CfbNoPadding() { super("cfb", CipherMode.CFB, CipherPadding.NOPADDING); }
   }

   public static class CfbPKCS5Padding extends AESCipher {
      public CfbPKCS5Padding() { super("cfb", CipherMode.CFB, CipherPadding.PKCS5PADDING); }
   }

   public static class OfbNoPadding extends AESCipher {
      public OfbNoPadding() { super("ofb", CipherMode.OFB, CipherPadding.NOPADDING); }
   }

   public static class OfbPKCS5Padding extends AESCipher {
      public OfbPKCS5Padding() { super("ofb", CipherMode.OFB, CipherPadding.PKCS5PADDING); }
   }

   public static class GcmNoPadding extends AESCipher {
      public GcmNoPadding() { super("gcm", CipherMode.GCM, CipherPadding.NOPADDING); }
   }

   public static class CcmNoPadding extends AESCipher {
      public CcmNoPadding() { super("ccm", CipherMode.CCM, CipherPadding.NOPADDING); }
   }
}
