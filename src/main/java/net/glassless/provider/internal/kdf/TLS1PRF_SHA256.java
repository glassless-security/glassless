package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * TLS 1.2 PRF using SHA-256.
 */
public class TLS1PRF_SHA256 extends AbstractTLSPRF {

   public TLS1PRF_SHA256(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "TLS1-PRF-SHA256", "SHA256");
   }
}
