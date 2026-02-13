package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA1AndAES_128 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA1AndAES_128() {
        super("PBEWithHmacSHA1AndAES_128", "SHA1", 128);
    }
}
