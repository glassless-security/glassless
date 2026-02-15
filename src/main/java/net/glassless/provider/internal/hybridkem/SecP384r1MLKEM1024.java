package net.glassless.provider.internal.hybridkem;

/**
 * SecP384r1MLKEM1024 hybrid KEM implementation.
 * Combines P-384 ECDH key agreement with ML-KEM-1024 for quantum-resistant key encapsulation.
 */
public class SecP384r1MLKEM1024 extends HybridKEM {
   public SecP384r1MLKEM1024() {
      super("SecP384r1MLKEM1024", "SecP384r1MLKEM1024", 64);
   }
}
