package net.glassless.provider.internal.mac;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * AES-GMAC implementation using OpenSSL.
 * GMAC (Galois Message Authentication Code) as defined in NIST SP 800-38D.
 */
public class AESGMACMac extends AbstractMac {

    public AESGMACMac() {
        super("GMAC", 16);  // GMAC produces a 128-bit (16 byte) tag
    }

    @Override
    protected int createParams() {
        // GMAC requires a cipher parameter
        return OpenSSLCrypto.createCipherParams("AES-128-GCM");
    }
}
