package net.glassless.provider.internal.mac;

/**
 * Poly1305 MAC implementation using OpenSSL.
 * Poly1305 is a fast, one-time authenticator defined in RFC 8439.
 */
public class Poly1305Mac extends AbstractMac {

    public Poly1305Mac() {
        super("Poly1305", 16);  // Poly1305 produces a 128-bit (16 byte) tag
    }
}
