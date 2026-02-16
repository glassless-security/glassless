package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * TLS 1.3 KDF implementation using SHA-256.
 *
 * This is the default hash for TLS 1.3 cipher suites using AES-128.
 */
public class TLS13KDF_SHA256 extends AbstractTLS13KDF {

   public TLS13KDF_SHA256(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "TLS13-KDF-SHA256", "SHA256");
   }
}
