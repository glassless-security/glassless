package net.glassless.provider.internal.keygen;

public class HmacSHA512KeyGenerator extends AbstractKeyGenerator {
    public HmacSHA512KeyGenerator() {
        super("HmacSHA512", 512, null); // Default 512 bits (64 bytes), any size allowed
    }
}
