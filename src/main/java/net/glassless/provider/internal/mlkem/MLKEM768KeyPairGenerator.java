package net.glassless.provider.internal.mlkem;

/**
 * KeyPairGenerator for ML-KEM-768.
 * Security level: Category 3 (192-bit classical security).
 */
public class MLKEM768KeyPairGenerator extends MLKEMKeyPairGenerator {

    public MLKEM768KeyPairGenerator() {
        super(MLKEM768, "ML-KEM-768");
    }
}
