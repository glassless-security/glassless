package net.glassless.provider.internal.mlkem;

/**
 * KeyPairGenerator for ML-KEM-512.
 * Security level: Category 1 (128-bit classical security).
 */
public class MLKEM512KeyPairGenerator extends MLKEMKeyPairGenerator {

    public MLKEM512KeyPairGenerator() {
        super(MLKEM512, "ML-KEM-512");
    }
}
