package net.glassless.provider.internal.keygen;

public class HmacSHA384KeyGenerator extends AbstractKeyGenerator {
    public HmacSHA384KeyGenerator() {
        super("HmacSHA384", 384, null); // Default 384 bits (48 bytes), any size allowed
    }
}
