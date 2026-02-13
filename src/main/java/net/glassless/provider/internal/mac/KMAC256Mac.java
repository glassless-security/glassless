package net.glassless.provider.internal.mac;

/**
 * KMAC256 implementation using OpenSSL.
 * KMAC (KECCAK Message Authentication Code) as defined in NIST SP 800-185.
 */
public class KMAC256Mac extends AbstractMac {

    public KMAC256Mac() {
        super("KMAC256", 64);  // Default output length is 512 bits (64 bytes)
    }
}
