package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA256AndAES_256 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA256AndAES_256() {
        super("PBEWithHmacSHA256AndAES_256", "SHA256", 256);
    }
}
