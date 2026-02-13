package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA512AndAES_128 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA512AndAES_128() {
        super("PBEWithHmacSHA512AndAES_128", "SHA512", 128);
    }
}
