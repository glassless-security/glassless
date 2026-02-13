package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * TLS 1.2 PRF using SHA-384.
 */
public class TLS1PRF_SHA384 extends AbstractTLSPRF {

   public TLS1PRF_SHA384(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "TLS1-PRF-SHA384", "SHA384");
   }
}
