package net.glassless.provider.internal.securerandom;

import java.io.Serial;

/**
 * NativePRNG SecureRandom implementation.
 * This is an alias for OpenSSLSecureRandom, which uses OpenSSL's
 * native random number generator (backed by system entropy).
 */
public class NativePRNG extends OpenSSLSecureRandom {

   @Serial
   private static final long serialVersionUID = 1L;

   public NativePRNG() {
      super();
   }
}
