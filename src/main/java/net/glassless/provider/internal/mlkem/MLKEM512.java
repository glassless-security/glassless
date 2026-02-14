package net.glassless.provider.internal.mlkem;

/**
 * KEMSpi implementation for ML-KEM-512.
 * Security level: Category 1 (128-bit classical security).
 * Shared secret size: 32 bytes.
 */
public class MLKEM512 extends MLKEM {

    public MLKEM512() {
        super("mlkem512", "ML-KEM-512", 32);
    }
}
