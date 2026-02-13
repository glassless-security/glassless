package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * AlgorithmParameters implementation for PBE (Password-Based Encryption).
 * Supports PBEParameterSpec containing salt, iteration count, and optional IV.
 */
public class PBEParameters extends AlgorithmParametersSpi {

    private byte[] salt;
    private int iterationCount;
    private byte[] iv;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof PBEParameterSpec pbeSpec)) {
            throw new InvalidParameterSpecException("Unsupported parameter spec: " +
                (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        this.salt = pbeSpec.getSalt().clone();
        this.iterationCount = pbeSpec.getIterationCount();

        AlgorithmParameterSpec nested = pbeSpec.getParameterSpec();
        if (nested instanceof IvParameterSpec ivSpec) {
            this.iv = ivSpec.getIV().clone();
        } else {
            this.iv = null;
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // Parse ASN.1 DER encoded PBES2 parameters
        // PBES2-params ::= SEQUENCE {
        //     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
        //     encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
        // }
        // PBKDF2-params ::= SEQUENCE {
        //     salt CHOICE { specified OCTET STRING, ... },
        //     iterationCount INTEGER (1..MAX),
        //     keyLength INTEGER (1..MAX) OPTIONAL,
        //     prf AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
        // }
        try {
            parseDER(params);
        } catch (Exception e) {
            throw new IOException("Failed to parse PBE parameters", e);
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
        if (paramSpec.isAssignableFrom(PBEParameterSpec.class)) {
            if (salt == null) {
                throw new InvalidParameterSpecException("PBE parameters not initialized");
            }
            if (iv != null) {
                return (T) new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(iv));
            }
            return (T) new PBEParameterSpec(salt, iterationCount);
        }
        throw new InvalidParameterSpecException("Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        if (salt == null) {
            throw new IOException("PBE parameters not initialized");
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
        if (salt != null) {
            return "PBE Parameters: salt length=" + salt.length + " bytes, iterations=" + iterationCount +
                   (iv != null ? ", IV length=" + iv.length + " bytes" : "");
        }
        return "PBE Parameters: <not initialized>";
    }

    private void parseDER(byte[] der) throws IOException {
        int[] offset = {0};

        // Expect SEQUENCE (PBES2-params)
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE tag");
        }
        int seqLen = readLength(der, offset);
        int seqEnd = offset[0] + seqLen;

        // Parse keyDerivationFunc (AlgorithmIdentifier with PBKDF2-params)
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE for keyDerivationFunc");
        }
        int kdfLen = readLength(der, offset);
        int kdfEnd = offset[0] + kdfLen;

        // Skip OID for PBKDF2
        if (der[offset[0]++] != 0x06) {
            throw new IOException("Expected OID");
        }
        int oidLen = readLength(der, offset);
        offset[0] += oidLen;

        // Parse PBKDF2-params
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE for PBKDF2-params");
        }
        int pbkdf2Len = readLength(der, offset);

        // Parse salt
        if (der[offset[0]++] != 0x04) {
            throw new IOException("Expected OCTET STRING for salt");
        }
        int saltLen = readLength(der, offset);
        this.salt = new byte[saltLen];
        System.arraycopy(der, offset[0], this.salt, 0, saltLen);
        offset[0] += saltLen;

        // Parse iteration count
        if (der[offset[0]++] != 0x02) {
            throw new IOException("Expected INTEGER for iteration count");
        }
        int intLen = readLength(der, offset);
        this.iterationCount = 0;
        for (int i = 0; i < intLen; i++) {
            this.iterationCount = (this.iterationCount << 8) | (der[offset[0]++] & 0xFF);
        }

        // Skip to encryptionScheme
        offset[0] = kdfEnd;

        // Parse encryptionScheme (AlgorithmIdentifier)
        if (offset[0] < seqEnd && der[offset[0]] == 0x30) {
            offset[0]++;
            int encLen = readLength(der, offset);
            int encEnd = offset[0] + encLen;

            // Skip OID for encryption algorithm
            if (der[offset[0]++] != 0x06) {
                throw new IOException("Expected OID for encryption algorithm");
            }
            oidLen = readLength(der, offset);
            offset[0] += oidLen;

            // Parse IV if present
            if (offset[0] < encEnd && der[offset[0]] == 0x04) {
                offset[0]++;
                int ivLen = readLength(der, offset);
                this.iv = new byte[ivLen];
                System.arraycopy(der, offset[0], this.iv, 0, ivLen);
            }
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
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

        // Build PBKDF2-params
        byte[] pbkdf2Params = buildPBKDF2Params();

        // Build keyDerivationFunc AlgorithmIdentifier
        byte[] pbkdf2Oid = {0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x05, 0x0C}; // 1.2.840.113549.1.5.12
        byte[] kdfAlgId = encodeSequence(concat(pbkdf2Oid, pbkdf2Params));

        // Build encryptionScheme AlgorithmIdentifier
        byte[] encScheme = buildEncryptionScheme();

        // Build PBES2-params SEQUENCE
        byte[] pbes2Params = encodeSequence(concat(kdfAlgId, encScheme));

        return pbes2Params;
    }

    private byte[] buildPBKDF2Params() {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

        // Salt as OCTET STRING
        baos.write(0x04);
        baos.write(salt.length);
        baos.write(salt, 0, salt.length);

        // Iteration count as INTEGER
        byte[] iterBytes = encodeInteger(iterationCount);
        baos.write(iterBytes, 0, iterBytes.length);

        return encodeSequence(baos.toByteArray());
    }

    private byte[] buildEncryptionScheme() {
        // AES-128-CBC OID: 2.16.840.1.101.3.4.1.2
        byte[] aesOid = {0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02};

        if (iv != null) {
            // IV as OCTET STRING
            byte[] ivEncoded = new byte[2 + iv.length];
            ivEncoded[0] = 0x04;
            ivEncoded[1] = (byte) iv.length;
            System.arraycopy(iv, 0, ivEncoded, 2, iv.length);
            return encodeSequence(concat(aesOid, ivEncoded));
        }
        return encodeSequence(aesOid);
    }

    private byte[] encodeSequence(byte[] content) {
        byte[] lenBytes = encodeLength(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = 0x30;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    private byte[] encodeInteger(int value) {
        if (value < 128) {
            return new byte[]{0x02, 0x01, (byte) value};
        } else if (value < 256) {
            return new byte[]{0x02, 0x02, 0x00, (byte) value};
        } else if (value < 32768) {
            return new byte[]{0x02, 0x02, (byte)(value >> 8), (byte) value};
        } else if (value < 8388608) {
            return new byte[]{0x02, 0x03, (byte)(value >> 16), (byte)(value >> 8), (byte) value};
        } else {
            return new byte[]{0x02, 0x04, (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte) value};
        }
    }

    private byte[] encodeLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        } else if (length < 256) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
        }
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
