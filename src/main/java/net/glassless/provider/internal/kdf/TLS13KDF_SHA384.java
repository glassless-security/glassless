package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * TLS 1.3 KDF implementation using SHA-384.
 *
 * This is used by TLS 1.3 cipher suites using AES-256.
 */
public class TLS13KDF_SHA384 extends AbstractTLS13KDF {

   public TLS13KDF_SHA384(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "TLS13-KDF-SHA384", "SHA384");
   }
}
