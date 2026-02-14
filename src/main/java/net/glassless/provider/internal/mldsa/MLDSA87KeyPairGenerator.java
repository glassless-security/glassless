package net.glassless.provider.internal.mldsa;

/**
 * KeyPairGenerator for ML-DSA-87.
 * Security level: Category 5 (256-bit classical security).
 */
public class MLDSA87KeyPairGenerator extends MLDSAKeyPairGenerator {

    public MLDSA87KeyPairGenerator() {
        super(MLDSA87, "ML-DSA-87");
    }
}
