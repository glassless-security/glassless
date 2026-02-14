package net.glassless.provider.internal.mldsa;

/**
 * KeyPairGenerator for ML-DSA-44.
 * Security level: Category 2 (128-bit classical security).
 */
public class MLDSA44KeyPairGenerator extends MLDSAKeyPairGenerator {

    public MLDSA44KeyPairGenerator() {
        super(MLDSA44, "ML-DSA-44");
    }
}
