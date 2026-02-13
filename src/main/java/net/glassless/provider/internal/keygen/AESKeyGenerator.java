package net.glassless.provider.internal.keygen;

public class AESKeyGenerator extends AbstractKeyGenerator {
    public AESKeyGenerator() {
        // AES supports 128, 192, and 256 bit keys
        super("AES", 128, new int[]{128, 192, 256});
    }
}
