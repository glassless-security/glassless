package net.glassless.provider.internal.hybridkem;

/**
 * X25519MLKEM768 hybrid KEM implementation.
 * Combines X25519 key agreement with ML-KEM-768 for quantum-resistant key encapsulation.
 */
public class X25519MLKEM768 extends HybridKEM {
   public X25519MLKEM768() {
      super("X25519MLKEM768", "X25519MLKEM768", 64);
   }
}
