package net.glassless.provider.internal.mac;

/**
 * KMAC128 implementation using OpenSSL.
 * KMAC (KECCAK Message Authentication Code) as defined in NIST SP 800-185.
 */
public class KMAC128Mac extends AbstractMac {

    public KMAC128Mac() {
        super("KMAC128", 32);  // Default output length is 256 bits (32 bytes)
    }
}
