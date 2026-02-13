package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;

/**
 * AlgorithmParameters implementation for Diffie-Hellman.
 * Supports DHParameterSpec containing p, g, and optional l values.
 */
public class DHParameters extends AlgorithmParametersSpi {

    private BigInteger p;
    private BigInteger g;
    private int l; // private value length (optional, 0 if not specified)

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof DHParameterSpec dhSpec)) {
            throw new InvalidParameterSpecException("Unsupported parameter spec: " +
                (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        this.p = dhSpec.getP();
        this.g = dhSpec.getG();
        this.l = dhSpec.getL();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // Parse ASN.1 DER encoded DH parameters
        // DHParameters ::= SEQUENCE {
        //     p INTEGER,
        //     g INTEGER,
        //     l INTEGER OPTIONAL
        // }
        try {
            parseDER(params);
        } catch (Exception e) {
            throw new IOException("Failed to parse DH parameters", e);
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
        if (paramSpec.isAssignableFrom(DHParameterSpec.class)) {
            if (p == null || g == null) {
                throw new InvalidParameterSpecException("DH parameters not initialized");
            }
            if (l > 0) {
                return (T) new DHParameterSpec(p, g, l);
            }
            return (T) new DHParameterSpec(p, g);
        }
        throw new InvalidParameterSpecException("Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        if (p == null || g == null) {
            throw new IOException("DH parameters not initialized");
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
        if (p != null && g != null) {
            return "DH Parameters: p=" + p.bitLength() + " bits" + (l > 0 ? ", l=" + l : "");
        }
        return "DH Parameters: <not initialized>";
    }

    private void parseDER(byte[] der) throws IOException {
        int[] offset = {0};

        // Expect SEQUENCE
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE tag");
        }
        int seqLen = readLength(der, offset);
        int seqEnd = offset[0] + seqLen;

        // Read p
        this.p = readInteger(der, offset);
        // Read g
        this.g = readInteger(der, offset);

        // Read l (optional)
        if (offset[0] < seqEnd && der[offset[0]] == 0x02) {
            BigInteger lValue = readInteger(der, offset);
            this.l = lValue.intValue();
        } else {
            this.l = 0;
        }
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
        byte[] gBytes = encodeInteger(g);
        byte[] lBytes = (l > 0) ? encodeInteger(BigInteger.valueOf(l)) : new byte[0];

        int contentLen = pBytes.length + gBytes.length + lBytes.length;
        byte[] lenBytes = encodeLength(contentLen);

        byte[] result = new byte[1 + lenBytes.length + contentLen];
        int pos = 0;
        result[pos++] = 0x30; // SEQUENCE tag
        System.arraycopy(lenBytes, 0, result, pos, lenBytes.length);
        pos += lenBytes.length;
        System.arraycopy(pBytes, 0, result, pos, pBytes.length);
        pos += pBytes.length;
        System.arraycopy(gBytes, 0, result, pos, gBytes.length);
        pos += gBytes.length;
        if (lBytes.length > 0) {
            System.arraycopy(lBytes, 0, result, pos, lBytes.length);
        }

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
