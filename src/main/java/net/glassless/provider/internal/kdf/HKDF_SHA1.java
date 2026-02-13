package net.glassless.provider.internal.kdf;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.KDFParameters;

/**
 * HKDF implementation using SHA-1 as the underlying hash function.
 * Note: SHA-1 is deprecated for most uses but supported for legacy compatibility.
 */
public class HKDF_SHA1 extends AbstractHKDF {

    public HKDF_SHA1(KDFParameters params) throws InvalidAlgorithmParameterException {
        super(params, "HKDF-SHA1", "SHA1", 20);
    }
}
