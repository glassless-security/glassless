package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA3_384 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA3_384() {
        super("PBKDF2WithHmacSHA3-384", "SHA3-384", 384);
    }
}
