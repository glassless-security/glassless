package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA256And8BIT extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA256And8BIT() {
        super("PBKDF2WithHmacSHA256And8BIT", "SHA256", 256, PasswordEncoding.EIGHT_BIT);
    }
}
