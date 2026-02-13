package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA512 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA512() {
        super("PBKDF2WithHmacSHA512", "SHA512", 512);
    }
}
