package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * X9.63 KDF using SHA-256.
 */
public class X963KDF_SHA256 extends AbstractX963KDF {

   public X963KDF_SHA256(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "X963KDF-SHA256", "SHA256");
   }
}
