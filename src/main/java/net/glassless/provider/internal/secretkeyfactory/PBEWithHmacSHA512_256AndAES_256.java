package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA512_256AndAES_256 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA512_256AndAES_256() {
        super("PBEWithHmacSHA512/256AndAES_256", "SHA512-256", 256);
    }
}
