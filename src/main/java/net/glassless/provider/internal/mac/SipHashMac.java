package net.glassless.provider.internal.mac;

/**
 * SipHash MAC implementation using OpenSSL.
 * SipHash is a fast short-input PRF defined in https://131002.net/siphash/.
 */
public class SipHashMac extends AbstractMac {

    public SipHashMac() {
        super("SIPHASH", 8);  // SipHash-2-4 produces a 64-bit (8 byte) tag by default
    }
}
