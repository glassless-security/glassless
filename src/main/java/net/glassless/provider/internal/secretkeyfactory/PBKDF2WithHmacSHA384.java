package net.glassless.provider.internal.secretkeyfactory;

public class PBKDF2WithHmacSHA384 extends AbstractPBKDF2SecretKeyFactory {
    public PBKDF2WithHmacSHA384() {
        super("PBKDF2WithHmacSHA384", "SHA384", 384);
    }
}
