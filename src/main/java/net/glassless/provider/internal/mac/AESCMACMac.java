package net.glassless.provider.internal.mac;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * AES-CMAC implementation using OpenSSL.
 * CMAC (Cipher-based Message Authentication Code) as defined in NIST SP 800-38B.
 */
public class AESCMACMac extends AbstractMac {

    public AESCMACMac() {
        super("CMAC", 16);  // AES-CMAC produces a 128-bit (16 byte) tag
    }

    @Override
    protected int createParams() {
        // CMAC requires a cipher parameter
        return OpenSSLCrypto.createCipherParams("AES-128-CBC");
    }
}
