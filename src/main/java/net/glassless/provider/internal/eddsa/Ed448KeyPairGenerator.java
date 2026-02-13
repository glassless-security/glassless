package net.glassless.provider.internal.eddsa;

import java.security.spec.NamedParameterSpec;

/**
 * KeyPairGenerator specifically for Ed448.
 */
public class Ed448KeyPairGenerator extends EdDSAKeyPairGenerator {

    public Ed448KeyPairGenerator() {
        try {
            initialize(NamedParameterSpec.ED448, null);
        } catch (Exception e) {
            // Should never happen
            throw new RuntimeException(e);
        }
    }
}
