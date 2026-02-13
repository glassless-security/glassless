package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA512And8BIT extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA512And8BIT() {
        super("PBKDF2WithHmacSHA512And8BIT", "SHA512", 512, PasswordEncoding.EIGHT_BIT);
    }
}
