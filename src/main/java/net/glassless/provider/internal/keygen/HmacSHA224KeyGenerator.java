package net.glassless.provider.internal.keygen;

public class HmacSHA224KeyGenerator extends AbstractKeyGenerator {
    public HmacSHA224KeyGenerator() {
        super("HmacSHA224", 224, null); // Default 224 bits (28 bytes), any size allowed
    }
}
