package net.glassless.provider.internal.cipher;

public class PBEWithHmacSHA512AndAES_256Cipher extends AbstractPBECipher {
    public PBEWithHmacSHA512AndAES_256Cipher() {
        super("aes-256-cbc", 32, CipherMode.CBC, "SHA512");
    }
}
