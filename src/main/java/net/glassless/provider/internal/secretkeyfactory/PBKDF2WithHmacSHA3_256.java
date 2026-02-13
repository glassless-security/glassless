package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA3_256 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA3_256() {
        super("PBKDF2WithHmacSHA3-256", "SHA3-256", 256);
    }
}
