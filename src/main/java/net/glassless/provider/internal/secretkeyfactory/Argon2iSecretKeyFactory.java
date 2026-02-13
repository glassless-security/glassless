package net.glassless.provider.internal.secretkeyfactory;

/**
 * SecretKeyFactory for Argon2i key derivation.
 *
 * Argon2i is data-independent and is recommended for password hashing
 * and key derivation where side-channel attacks are a concern.
 *
 * Requires OpenSSL 3.2 or later.
 */
public class Argon2iSecretKeyFactory extends AbstractArgon2SecretKeyFactory {

   public Argon2iSecretKeyFactory() {
      super("Argon2i", "ARGON2I");
   }
}
