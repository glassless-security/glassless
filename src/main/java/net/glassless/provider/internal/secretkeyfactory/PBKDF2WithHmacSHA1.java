package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA1 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA1() {
        super("PBKDF2WithHmacSHA1", "SHA1", 160);
    }
}
