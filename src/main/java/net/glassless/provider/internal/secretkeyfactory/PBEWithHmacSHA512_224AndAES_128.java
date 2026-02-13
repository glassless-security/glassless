package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA512_224AndAES_128 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA512_224AndAES_128() {
        super("PBEWithHmacSHA512/224AndAES_128", "SHA512-224", 128);
    }
}
