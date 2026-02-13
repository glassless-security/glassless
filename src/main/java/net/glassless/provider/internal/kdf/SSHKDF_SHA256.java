package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * SSH KDF using SHA-256.
 */
public class SSHKDF_SHA256 extends AbstractSSHKDF {

   public SSHKDF_SHA256(KDFParameters params) throws InvalidAlgorithmParameterException {
      super(params, "SSHKDF-SHA256", "SHA256");
   }
}
