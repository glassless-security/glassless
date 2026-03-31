package net.glassless.provider.internal.cipher;

public class DESedeEcbNoPaddingCipher extends AbstractCipher {
   public DESedeEcbNoPaddingCipher() {
      super("des-ede3-ecb", CipherMode.ECB, CipherPadding.NOPADDING);
   }
}
