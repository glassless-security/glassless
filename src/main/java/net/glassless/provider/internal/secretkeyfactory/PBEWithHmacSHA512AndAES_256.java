package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA512AndAES_256 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA512AndAES_256() {
        super("PBEWithHmacSHA512AndAES_256", "SHA512", 256);
    }
}
