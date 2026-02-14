package net.glassless.provider.internal.mlkem;

/**
 * KEMSpi implementation for ML-KEM-1024.
 * Security level: Category 5 (256-bit classical security).
 * Shared secret size: 32 bytes.
 */
public class MLKEM1024 extends MLKEM {

    public MLKEM1024() {
        super("mlkem1024", "ML-KEM-1024", 32);
    }
}
