package net.glassless.provider.internal.keygen;

public class HmacSHA256KeyGenerator extends AbstractKeyGenerator {
    public HmacSHA256KeyGenerator() {
        super("HmacSHA256", 256, null); // Default 256 bits (32 bytes), any size allowed
    }
}
