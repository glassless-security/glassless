package net.glassless.provider.internal.secretkeyfactory;

/**
 * SecretKeyFactory for Argon2d key derivation.
 *
 * Argon2d is data-dependent and is faster and more resistant to GPU
 * cracking attacks, but is more vulnerable to side-channel attacks.
 * Use Argon2id for most applications.
 *
 * Requires OpenSSL 3.2 or later.
 */
public class Argon2dSecretKeyFactory extends AbstractArgon2SecretKeyFactory {

   public Argon2dSecretKeyFactory() {
      super("Argon2d", "ARGON2D");
   }
}
