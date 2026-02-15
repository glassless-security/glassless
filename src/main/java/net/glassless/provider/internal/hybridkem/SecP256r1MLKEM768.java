package net.glassless.provider.internal.hybridkem;

/**
 * SecP256r1MLKEM768 hybrid KEM implementation.
 * Combines P-256 ECDH key agreement with ML-KEM-768 for quantum-resistant key encapsulation.
 */
public class SecP256r1MLKEM768 extends HybridKEM {
   public SecP256r1MLKEM768() {
      super("SecP256r1MLKEM768", "SecP256r1MLKEM768", 64);
   }
}
