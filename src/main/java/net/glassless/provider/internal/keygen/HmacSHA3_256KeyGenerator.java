package net.glassless.provider.internal.keygen;

public class HmacSHA3_256KeyGenerator extends AbstractKeyGenerator {
    public HmacSHA3_256KeyGenerator() {
        super("HmacSHA3-256", 256, null);
    }
}
