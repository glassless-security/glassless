package net.glassless.provider.internal.cipher;

public class PBEWithHmacSHA384AndAES_256Cipher extends AbstractPBECipher {
    public PBEWithHmacSHA384AndAES_256Cipher() {
        super("aes-256-cbc", 32, CipherMode.CBC, "SHA384");
    }
}
