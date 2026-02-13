package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

/**
 * AlgorithmParameters implementation for DESede (Triple DES).
 * Supports IvParameterSpec for the initialization vector.
 */
public class DESedeParameters extends AlgorithmParametersSpi {

    private byte[] iv;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof IvParameterSpec ivSpec)) {
            throw new InvalidParameterSpecException("Unsupported parameter spec: " +
                (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        this.iv = ivSpec.getIV().clone();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // Parse ASN.1 DER encoded IV (OCTET STRING)
        if (params == null || params.length < 2) {
            throw new IOException("Invalid DER encoding");
        }
        if (params[0] != 0x04) { // OCTET STRING tag
            throw new IOException("Expected OCTET STRING tag");
        }
        int len = params[1] & 0xFF;
        if (params.length < 2 + len) {
            throw new IOException("Invalid DER length");
        }
        this.iv = new byte[len];
        System.arraycopy(params, 2, this.iv, 0, len);
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        if (format == null || format.equalsIgnoreCase("ASN.1") || format.equalsIgnoreCase("DER")) {
            engineInit(params);
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec.isAssignableFrom(IvParameterSpec.class)) {
            if (iv == null) {
                throw new InvalidParameterSpecException("IV not initialized");
            }
            return (T) new IvParameterSpec(iv);
        }
        throw new InvalidParameterSpecException("Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        if (iv == null) {
            throw new IOException("IV not initialized");
        }
        // Encode as OCTET STRING
        byte[] result = new byte[2 + iv.length];
        result[0] = 0x04; // OCTET STRING tag
        result[1] = (byte) iv.length;
        System.arraycopy(iv, 0, result, 2, iv.length);
        return result;
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (format == null || format.equalsIgnoreCase("ASN.1") || format.equalsIgnoreCase("DER")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    @Override
    protected String engineToString() {
        if (iv != null) {
            return "DESede Parameters: IV length=" + iv.length + " bytes";
        }
        return "DESede Parameters: <not initialized>";
    }
}
