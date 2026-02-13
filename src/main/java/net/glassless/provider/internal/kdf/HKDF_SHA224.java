package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * HKDF implementation using SHA-224 as the underlying hash function.
 */
public class HKDF_SHA224 extends AbstractHKDF {

    public HKDF_SHA224(KDFParameters params) throws InvalidAlgorithmParameterException {
        super(params, "HKDF-SHA224", "SHA224", 28);
    }
}
