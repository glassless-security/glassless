package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.GCMParameterSpec;

/**
 * AlgorithmParameters implementation for GCM (Galois/Counter Mode).
 * Supports GCMParameterSpec containing IV and authentication tag length.
 */
public class GCMParameters extends AlgorithmParametersSpi {

    private byte[] iv;
    private int tLen; // authentication tag length in bits

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof GCMParameterSpec gcmSpec)) {
            throw new InvalidParameterSpecException("Unsupported parameter spec: " +
                (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        this.iv = gcmSpec.getIV().clone();
        this.tLen = gcmSpec.getTLen();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // Parse ASN.1 DER encoded GCM parameters
        // GCMParameters ::= SEQUENCE {
        //     aes-nonce OCTET STRING,
        //     aes-ICVlen AES-GCM-ICVlen DEFAULT 12
        // }
        // AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)
        try {
            parseDER(params);
        } catch (Exception e) {
            throw new IOException("Failed to parse GCM parameters", e);
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
        if (paramSpec.isAssignableFrom(GCMParameterSpec.class)) {
            if (iv == null) {
                throw new InvalidParameterSpecException("GCM parameters not initialized");
            }
            return (T) new GCMParameterSpec(tLen, iv);
        }
        throw new InvalidParameterSpecException("Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        if (iv == null) {
            throw new IOException("GCM parameters not initialized");
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
        if (iv != null) {
            return "GCM Parameters: IV length=" + iv.length + " bytes, tag length=" + tLen + " bits";
        }
        return "GCM Parameters: <not initialized>";
    }

    private void parseDER(byte[] der) throws IOException {
        int[] offset = {0};

        // Expect SEQUENCE
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE tag");
        }
        int seqLen = readLength(der, offset);
        int seqEnd = offset[0] + seqLen;

        // Read IV (OCTET STRING)
        if (der[offset[0]++] != 0x04) {
            throw new IOException("Expected OCTET STRING tag for IV");
        }
        int ivLen = readLength(der, offset);
        this.iv = new byte[ivLen];
        System.arraycopy(der, offset[0], this.iv, 0, ivLen);
        offset[0] += ivLen;

        // Read tag length (optional INTEGER, default 12 bytes = 96 bits)
        if (offset[0] < seqEnd && der[offset[0]] == 0x02) {
            offset[0]++; // skip tag
            int intLen = readLength(der, offset);
            int tLenBytes = 0;
            for (int i = 0; i < intLen; i++) {
                tLenBytes = (tLenBytes << 8) | (der[offset[0]++] & 0xFF);
            }
            this.tLen = tLenBytes * 8; // convert bytes to bits
        } else {
            this.tLen = 128; // default 16 bytes = 128 bits
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

    private byte[] encodeDER() {
        // Encode IV as OCTET STRING
        byte[] ivEncoded = new byte[2 + iv.length];
        ivEncoded[0] = 0x04;
        ivEncoded[1] = (byte) iv.length;
        System.arraycopy(iv, 0, ivEncoded, 2, iv.length);

        // Encode tag length as INTEGER (in bytes)
        int tLenBytes = tLen / 8;
        byte[] tLenEncoded = new byte[3];
        tLenEncoded[0] = 0x02;
        tLenEncoded[1] = 0x01;
        tLenEncoded[2] = (byte) tLenBytes;

        // Encode SEQUENCE
        int contentLen = ivEncoded.length + tLenEncoded.length;
        byte[] result = new byte[2 + contentLen];
        result[0] = 0x30;
        result[1] = (byte) contentLen;
        System.arraycopy(ivEncoded, 0, result, 2, ivEncoded.length);
        System.arraycopy(tLenEncoded, 0, result, 2 + ivEncoded.length, tLenEncoded.length);

        return result;
    }
}
