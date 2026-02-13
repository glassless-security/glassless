package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA256AndAES_128 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA256AndAES_128() {
        super("PBEWithHmacSHA256AndAES_128", "SHA256", 128);
    }
}
