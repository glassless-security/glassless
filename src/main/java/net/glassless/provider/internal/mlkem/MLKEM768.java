package net.glassless.provider.internal.mlkem;

/**
 * KEMSpi implementation for ML-KEM-768.
 * Security level: Category 3 (192-bit classical security).
 * Shared secret size: 32 bytes.
 */
public class MLKEM768 extends MLKEM {

    public MLKEM768() {
        super("mlkem768", "ML-KEM-768", 32);
    }
}
