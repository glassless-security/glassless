package net.glassless.provider.internal.hybridkem;

/**
 * X448MLKEM1024 hybrid KEM implementation.
 * Combines X448 key agreement with ML-KEM-1024 for quantum-resistant key encapsulation.
 */
public class X448MLKEM1024 extends HybridKEM {
   public X448MLKEM1024() {
      super("X448MLKEM1024", "X448MLKEM1024", 64);
   }
}
