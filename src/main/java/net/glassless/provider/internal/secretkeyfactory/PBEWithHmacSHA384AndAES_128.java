package net.glassless.provider.internal.secretkeyfactory;

public class PBEWithHmacSHA384AndAES_128 extends AbstractPBES2SecretKeyFactory {
    public PBEWithHmacSHA384AndAES_128() {
        super("PBEWithHmacSHA384AndAES_128", "SHA384", 128);
    }
}
