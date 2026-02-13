package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA256 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA256() {
        super("PBKDF2WithHmacSHA256", "SHA256", 256);
    }
}
