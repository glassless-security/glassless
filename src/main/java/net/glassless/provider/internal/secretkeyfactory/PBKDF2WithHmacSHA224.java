package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA224 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA224() {
        super("PBKDF2WithHmacSHA224", "SHA224", 224);
    }
}
