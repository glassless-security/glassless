package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA512_224AndAES_256 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA512_224AndAES_256() {
        super("PBEWithHmacSHA512/224AndAES_256", "SHA512-224", 256);
    }
}
