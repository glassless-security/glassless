package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA512_256AndAES_128 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA512_256AndAES_128() {
        super("PBEWithHmacSHA512/256AndAES_128", "SHA512-256", 128);
    }
}
