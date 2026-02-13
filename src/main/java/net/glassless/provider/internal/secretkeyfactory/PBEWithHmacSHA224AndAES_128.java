package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA224AndAES_128 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA224AndAES_128() {
        super("PBEWithHmacSHA224AndAES_128", "SHA224", 128);
    }
}
