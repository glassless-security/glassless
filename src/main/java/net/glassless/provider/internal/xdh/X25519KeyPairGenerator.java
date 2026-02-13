package net.glassless.provider.internal.xdh;

import java.security.spec.NamedParameterSpec;

/**
 * KeyPairGenerator specifically for X25519.
 */
public class X25519KeyPairGenerator extends XDHKeyPairGenerator {

    public X25519KeyPairGenerator() {
        try {
            initialize(NamedParameterSpec.X25519, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
