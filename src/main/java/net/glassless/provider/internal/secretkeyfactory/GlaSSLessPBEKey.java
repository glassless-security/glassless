package net.glassless.provider.internal.secretkeyfactory;

import java.io.Serial;
import java.nio.charset.StandardCharsets;

import javax.crypto.interfaces.PBEKey;

/**
 * PBEKey implementation that wraps a password for deferred key derivation.
 * Used when PKCS12KeyStore or other callers create a key with just the password,
 * deferring salt/iteration/key derivation to the cipher's init method.
 */
public class GlaSSLessPBEKey implements PBEKey {
   @Serial
   private static final long serialVersionUID = 1L;

   private char[] password;
   private final String algorithm;

   GlaSSLessPBEKey(char[] password, String algorithm) {
      this.password = password.clone();
      this.algorithm = algorithm;
   }

   @Override
   public char[] getPassword() {
      return password.clone();
   }

   @Override
   public byte[] getSalt() {
      return null;
   }

   @Override
   public int getIterationCount() {
      return 0;
   }

   @Override
   public String getAlgorithm() {
      return algorithm;
   }

   @Override
   public String getFormat() {
      return "RAW";
   }

   @Override
   public byte[] getEncoded() {
      return new String(password).getBytes(StandardCharsets.UTF_8);
   }

   @Override
   public void destroy() {
      java.util.Arrays.fill(password, '\0');
   }

   @Override
   public boolean isDestroyed() {
      for (char c : password) {
         if (c != '\0') return false;
      }
      return true;
   }
}
