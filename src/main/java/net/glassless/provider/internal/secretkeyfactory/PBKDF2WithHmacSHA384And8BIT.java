package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA384And8BIT extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA384And8BIT() {
        super("PBKDF2WithHmacSHA384And8BIT", "SHA384", 384, PasswordEncoding.EIGHT_BIT);
    }
}
