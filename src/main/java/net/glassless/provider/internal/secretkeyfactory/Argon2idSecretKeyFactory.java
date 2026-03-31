package net.glassless.provider.internal.secretkeyfactory;

/**
 * SecretKeyFactory for Argon2id key derivation.
 * <p>
 * Argon2id is a hybrid of Argon2d and Argon2i, providing both resistance
 * to side-channel attacks and GPU cracking. It is the recommended variant
 * for password hashing.
 * <p>
 * Requires OpenSSL 3.2 or later.
 */
public class Argon2idSecretKeyFactory extends AbstractArgon2SecretKeyFactory {

   public Argon2idSecretKeyFactory() {
      super("Argon2id", "ARGON2ID");
   }
}
