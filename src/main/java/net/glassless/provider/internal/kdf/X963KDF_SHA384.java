package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * X9.63 KDF using SHA-384.
 */
public class X963KDF_SHA384 extends AbstractX963KDF {

   public X963KDF_SHA384(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "X963KDF-SHA384", "SHA384");
   }
}
