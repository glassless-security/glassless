package net.glassless.provider.internal.xdh;

import java.security.spec.NamedParameterSpec;

/**
 * KeyPairGenerator specifically for X448.
 */
public class X448KeyPairGenerator extends XDHKeyPairGenerator {

    public X448KeyPairGenerator() {
        try {
            initialize(NamedParameterSpec.X448, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
