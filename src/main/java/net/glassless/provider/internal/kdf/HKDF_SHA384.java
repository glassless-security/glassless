package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * HKDF implementation using SHA-384 as the underlying hash function.
 */
public class HKDF_SHA384 extends AbstractHKDF {

    public HKDF_SHA384(KDFParameters params) throws InvalidAlgorithmParameterException {
        super(params, "HKDF-SHA384", "SHA384", 48);
    }
}
