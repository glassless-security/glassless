package net.glassless.provider.internal.algparamgen;

import static net.glassless.provider.GlaSSLessProvider.PROVIDER_NAME;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAGenParameterSpec;
import java.security.spec.DSAParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * AlgorithmParameterGenerator for DSA.
 * Generates DSA domain parameters (p, q, g) using OpenSSL.
 */
public class DSAParameterGenerator extends AbstractParameterGenerator {

   private int primePBits = 2048;
   private int primeQBits = 256;
   private SecureRandom random;

   public DSAParameterGenerator() {
      super("DSA");
   }

   @Override
   protected void engineInit(int size, SecureRandom random) {
      if (size < 512 || size > 8192) {
         throw new InvalidParameterException("Key size must be between 512 and 8192 bits");
      }
      if (size % 64 != 0) {
         throw new InvalidParameterException("Key size must be a multiple of 64");
      }
      this.primePBits = size;
      if (size <= 1024) {
         this.primeQBits = 160;
      } else {
         this.primeQBits = 256;
      }
      this.random = random;
   }

   @Override
   protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (genParamSpec instanceof DSAGenParameterSpec dsaGenSpec) {
         this.primePBits = dsaGenSpec.getPrimePLength();
         this.primeQBits = dsaGenSpec.getSubprimeQLength();
         this.random = random;
      } else {
         throw new InvalidAlgorithmParameterException(
            "Unsupported parameter spec: " + (genParamSpec == null ? "null" : genParamSpec.getClass().getName()));
      }
   }

   @Override
   protected void configureParameters(MemorySegment ctx) throws Throwable {
      int result = OpenSSLCrypto.EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, primePBits);
      if (result != 1) {
         throw new ProviderException("Failed to set DSA key size");
      }

      result = OpenSSLCrypto.EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, primeQBits);
      if (result != 1) {
         throw new ProviderException("Failed to set DSA Q size");
      }
   }

   @Override
   protected AlgorithmParameters extractParameters(MemorySegment pkey, Arena arena) throws Throwable {
      BigInteger p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "p", arena);
      BigInteger q = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "q", arena);
      BigInteger g = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "g", arena);

      DSAParameterSpec dsaSpec = new DSAParameterSpec(p, q, g);

      AlgorithmParameters params = AlgorithmParameters.getInstance("DSA", PROVIDER_NAME);
      params.init(dsaSpec);
      return params;
   }
}
