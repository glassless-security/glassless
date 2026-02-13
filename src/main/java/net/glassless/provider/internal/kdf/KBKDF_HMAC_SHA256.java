package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * KBKDF (SP 800-108) using HMAC-SHA256.
 */
public class KBKDF_HMAC_SHA256 extends AbstractKBKDF {

   public KBKDF_HMAC_SHA256(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "KBKDF-HMAC-SHA256", "HMAC", "SHA256");
   }
}
