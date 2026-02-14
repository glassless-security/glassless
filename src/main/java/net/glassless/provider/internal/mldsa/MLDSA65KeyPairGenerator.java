package net.glassless.provider.internal.mldsa;

/**
 * KeyPairGenerator for ML-DSA-65.
 * Security level: Category 3 (192-bit classical security).
 */
public class MLDSA65KeyPairGenerator extends MLDSAKeyPairGenerator {

    public MLDSA65KeyPairGenerator() {
        super(MLDSA65, "ML-DSA-65");
    }
}
