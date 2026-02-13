package net.glassless.provider.internal.signature;

import java.lang.foreign.MemorySegment;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for RSA-PSS signatures.
 * Configures PKCS#1 v2.1 PSS padding with digest-length salt.
 */
public abstract class AbstractRSAPSSSignature extends AbstractSignature {

    protected AbstractRSAPSSSignature(String digestAlgorithm) {
        super(digestAlgorithm, KeyType.RSA_PSS);
    }

    @Override
    protected void configureContext(MemorySegment pkeyCtx) throws Throwable {
        // Set RSA padding to PSS
        int result = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, OpenSSLCrypto.RSA_PKCS1_PSS_PADDING);
        if (result <= 0) {
            throw new IllegalStateException("Failed to set RSA-PSS padding");
        }

        // Set salt length to digest length (standard for RSASSA-PSS)
        result = OpenSSLCrypto.EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, OpenSSLCrypto.RSA_PSS_SALTLEN_DIGEST);
        if (result <= 0) {
            throw new IllegalStateException("Failed to set RSA-PSS salt length");
        }
    }
}
