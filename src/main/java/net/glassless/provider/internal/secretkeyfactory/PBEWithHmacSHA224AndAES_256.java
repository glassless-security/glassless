package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA224AndAES_256 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA224AndAES_256() {
        super("PBEWithHmacSHA224AndAES_256", "SHA224", 256);
    }
}
