package net.glassless.provider.internal.cipher;

import net.glassless.provider.internal.OpenSSLCrypto;

enum RSAPadding {
    NOPADDING(OpenSSLCrypto.RSA_NO_PADDING),
    PKCS1PADDING(OpenSSLCrypto.RSA_PKCS1_PADDING),
    OAEPPADDING(OpenSSLCrypto.RSA_PKCS1_OAEP_PADDING);

    private final int opensslPadding;

    RSAPadding(int opensslPadding) {
        this.opensslPadding = opensslPadding;
    }

    public int getOpenSSLPadding() {
        return opensslPadding;
    }
}
