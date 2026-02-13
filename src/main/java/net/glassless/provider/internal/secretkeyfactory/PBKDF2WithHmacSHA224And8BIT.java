package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA224And8BIT extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA224And8BIT() {
        super("PBKDF2WithHmacSHA224And8BIT", "SHA224", 224, PasswordEncoding.EIGHT_BIT);
    }
}
