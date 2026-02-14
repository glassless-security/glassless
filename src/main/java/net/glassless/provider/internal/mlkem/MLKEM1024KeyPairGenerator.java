package net.glassless.provider.internal.mlkem;

/**
 * KeyPairGenerator for ML-KEM-1024.
 * Security level: Category 5 (256-bit classical security).
 */
public class MLKEM1024KeyPairGenerator extends MLKEMKeyPairGenerator {

    public MLKEM1024KeyPairGenerator() {
        super(MLKEM1024, "ML-KEM-1024");
    }
}
