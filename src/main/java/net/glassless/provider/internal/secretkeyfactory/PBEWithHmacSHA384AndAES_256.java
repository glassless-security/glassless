package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA384AndAES_256 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA384AndAES_256() {
        super("PBEWithHmacSHA384AndAES_256", "SHA384", 256);
    }
}
