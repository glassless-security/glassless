package net.glassless.provider.internal.eddsa;

import java.security.spec.NamedParameterSpec;

/**
 * KeyPairGenerator specifically for Ed25519.
 */
public class Ed25519KeyPairGenerator extends EdDSAKeyPairGenerator {

    public Ed25519KeyPairGenerator() {
        try {
            initialize(NamedParameterSpec.ED25519, null);
        } catch (Exception e) {
            // Should never happen
            throw new RuntimeException(e);
        }
    }
}
