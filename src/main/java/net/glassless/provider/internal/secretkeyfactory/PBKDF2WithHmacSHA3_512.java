package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA3_512 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA3_512() {
        super("PBKDF2WithHmacSHA3-512", "SHA3-512", 512);
    }
}
