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

import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * AlgorithmParameterGenerator for Diffie-Hellman.
 * Generates DH domain parameters (p, g) using OpenSSL.
 */
public class DHParameterGenerator extends AbstractParameterGenerator {

   private int primeSize = 2048;
   private int exponentSize = 256;
   private SecureRandom random;

   public DHParameterGenerator() {
      super("DH");
   }

   @Override
   protected void engineInit(int size, SecureRandom random) {
      if (size < 512 || size > 8192) {
         throw new InvalidParameterException("Prime size must be between 512 and 8192 bits");
      }
      if (size % 64 != 0) {
         throw new InvalidParameterException("Prime size must be a multiple of 64");
      }
      this.primeSize = size;
      this.random = random;
   }

   @Override
   protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (genParamSpec instanceof DHGenParameterSpec dhGenSpec) {
         this.primeSize = dhGenSpec.getPrimeSize();
         this.exponentSize = dhGenSpec.getExponentSize();
         this.random = random;
      } else {
         throw new InvalidAlgorithmParameterException(
            "Unsupported parameter spec: " + (genParamSpec == null ? "null" : genParamSpec.getClass().getName()));
      }
   }

   @Override
   protected void configureParameters(MemorySegment ctx) throws Throwable {
      int result = OpenSSLCrypto.EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, primeSize);
      if (result != 1) {
         throw new ProviderException("Failed to set DH prime length");
      }

      result = OpenSSLCrypto.EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, 2);
      if (result != 1) {
         throw new ProviderException("Failed to set DH generator");
      }
   }

   @Override
   protected AlgorithmParameters extractParameters(MemorySegment pkey, Arena arena) throws Throwable {
      BigInteger p = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "p", arena);
      BigInteger g = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "g", arena);

      DHParameterSpec dhSpec;
      if (exponentSize > 0) {
         dhSpec = new DHParameterSpec(p, g, exponentSize);
      } else {
         dhSpec = new DHParameterSpec(p, g);
      }

      AlgorithmParameters params = AlgorithmParameters.getInstance("DH", PROVIDER_NAME);
      params.init(dhSpec);
      return params;
   }
}
