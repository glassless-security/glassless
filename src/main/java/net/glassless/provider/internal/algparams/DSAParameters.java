package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * AlgorithmParameters implementation for DSA.
 * Supports DSAParameterSpec containing p, q, and g values.
 */
public class DSAParameters extends AlgorithmParametersSpi {

    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof DSAParameterSpec dsaSpec)) {
            throw new InvalidParameterSpecException("Unsupported parameter spec: " +
                (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        this.p = dsaSpec.getP();
        this.q = dsaSpec.getQ();
        this.g = dsaSpec.getG();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // Parse ASN.1 DER encoded DSA parameters
        // DSAParameters ::= SEQUENCE {
        //     p INTEGER,
        //     q INTEGER,
        //     g INTEGER
        // }
        try {
            parseDER(params);
        } catch (Exception e) {
            throw new IOException("Failed to parse DSA parameters", e);
        }
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
        if (paramSpec.isAssignableFrom(DSAParameterSpec.class)) {
            if (p == null || q == null || g == null) {
                throw new InvalidParameterSpecException("DSA parameters not initialized");
            }
            return (T) new DSAParameterSpec(p, q, g);
        }
        throw new InvalidParameterSpecException("Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        if (p == null || q == null || g == null) {
            throw new IOException("DSA parameters not initialized");
        }
        return encodeDER();
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
        if (p != null && q != null && g != null) {
            return "DSA Parameters: p=" + p.bitLength() + " bits, q=" + q.bitLength() + " bits";
        }
        return "DSA Parameters: <not initialized>";
    }

    private void parseDER(byte[] der) throws IOException {
        int[] offset = {0};

        // Expect SEQUENCE
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE tag");
        }
        int seqLen = readLength(der, offset);

        // Read p
        this.p = readInteger(der, offset);
        // Read q
        this.q = readInteger(der, offset);
        // Read g
        this.g = readInteger(der, offset);
    }

    private int readLength(byte[] der, int[] offset) throws IOException {
        int b = der[offset[0]++] & 0xFF;
        if (b < 128) {
            return b;
        }
        int numBytes = b & 0x7F;
        int length = 0;
        for (int i = 0; i < numBytes; i++) {
            length = (length << 8) | (der[offset[0]++] & 0xFF);
        }
        return length;
    }

    private BigInteger readInteger(byte[] der, int[] offset) throws IOException {
        if (der[offset[0]++] != 0x02) {
            throw new IOException("Expected INTEGER tag");
        }
        int len = readLength(der, offset);
        byte[] intBytes = new byte[len];
        System.arraycopy(der, offset[0], intBytes, 0, len);
        offset[0] += len;
        return new BigInteger(intBytes);
    }

    private byte[] encodeDER() {
        byte[] pBytes = encodeInteger(p);
        byte[] qBytes = encodeInteger(q);
        byte[] gBytes = encodeInteger(g);

        int contentLen = pBytes.length + qBytes.length + gBytes.length;
        byte[] lenBytes = encodeLength(contentLen);

        byte[] result = new byte[1 + lenBytes.length + contentLen];
        int pos = 0;
        result[pos++] = 0x30; // SEQUENCE tag
        System.arraycopy(lenBytes, 0, result, pos, lenBytes.length);
        pos += lenBytes.length;
        System.arraycopy(pBytes, 0, result, pos, pBytes.length);
        pos += pBytes.length;
        System.arraycopy(qBytes, 0, result, pos, qBytes.length);
        pos += qBytes.length;
        System.arraycopy(gBytes, 0, result, pos, gBytes.length);

        return result;
    }

    private byte[] encodeInteger(BigInteger value) {
        byte[] valueBytes = value.toByteArray();
        byte[] lenBytes = encodeLength(valueBytes.length);
        byte[] result = new byte[1 + lenBytes.length + valueBytes.length];
        result[0] = 0x02; // INTEGER tag
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(valueBytes, 0, result, 1 + lenBytes.length, valueBytes.length);
        return result;
    }

    private byte[] encodeLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        } else if (length < 256) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else if (length < 65536) {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
        } else {
            return new byte[]{(byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length};
        }
    }
}
