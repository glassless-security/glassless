package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA3_224 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA3_224() {
        super("PBKDF2WithHmacSHA3-224", "SHA3-224", 224);
    }
}
