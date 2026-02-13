package net.glassless.provider.internal.keygen;

public class HmacSHA3_512KeyGenerator extends AbstractKeyGenerator {
    public HmacSHA3_512KeyGenerator() {
        super("HmacSHA3-512", 512, null);
    }
}
