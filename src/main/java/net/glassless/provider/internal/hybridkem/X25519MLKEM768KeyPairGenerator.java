package net.glassless.provider.internal.hybridkem;

/**
 * KeyPairGenerator for X25519MLKEM768 hybrid KEM.
 */
public class X25519MLKEM768KeyPairGenerator extends HybridKEMKeyPairGenerator {
   public X25519MLKEM768KeyPairGenerator() {
      super("X25519MLKEM768", "X25519MLKEM768");
   }
}
