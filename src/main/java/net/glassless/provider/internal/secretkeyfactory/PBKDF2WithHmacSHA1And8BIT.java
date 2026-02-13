package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA1And8BIT extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA1And8BIT() {
        super("PBKDF2WithHmacSHA1And8BIT", "SHA1", 160, PasswordEncoding.EIGHT_BIT);
    }
}
