package net.glassless.provider.internal.cipher;

/**
 * ChaCha20-Poly1305 AEAD cipher implementation.
 *
 * Key size: 256 bits (32 bytes)
 * Nonce size: 96 bits (12 bytes)
 * Tag size: 128 bits (16 bytes)
 */
public class ChaCha20Poly1305Cipher extends AbstractCipher {
    public ChaCha20Poly1305Cipher() {
        super("chacha20-poly1305", 32, CipherMode.POLY1305, CipherPadding.NOPADDING);
    }
}
