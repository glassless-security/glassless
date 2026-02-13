package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * HKDF implementation using SHA-256 as the underlying hash function.
 */
public class HKDF_SHA256 extends AbstractHKDF {

    public HKDF_SHA256(KDFParameters params) throws InvalidAlgorithmParameterException {
        super(params, "HKDF-SHA256", "SHA256", 32);
    }
}
