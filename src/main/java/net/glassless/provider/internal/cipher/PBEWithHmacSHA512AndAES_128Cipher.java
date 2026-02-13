package net.glassless.provider.internal.cipher;

public class PBEWithHmacSHA512AndAES_128Cipher extends AbstractPBECipher {
    public PBEWithHmacSHA512AndAES_128Cipher() {
        super("aes-128-cbc", 16, CipherMode.CBC, "SHA512");
    }
}
