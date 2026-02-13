package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * HKDF implementation using SHA-512 as the underlying hash function.
 */
public class HKDF_SHA512 extends AbstractHKDF {

    public HKDF_SHA512(KDFParameters params) throws InvalidAlgorithmParameterException {
        super(params, "HKDF-SHA512", "SHA512", 64);
    }
}
