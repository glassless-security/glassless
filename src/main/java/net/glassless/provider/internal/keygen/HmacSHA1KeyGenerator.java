package net.glassless.provider.internal.keygen;

public class HmacSHA1KeyGenerator extends AbstractKeyGenerator {
    public HmacSHA1KeyGenerator() {
        super("HmacSHA1", 160, null); // Default 160 bits (20 bytes), any size allowed
    }
}
