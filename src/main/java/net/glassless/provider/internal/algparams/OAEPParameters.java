package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * AlgorithmParameters implementation for RSA-OAEP.
 * Supports OAEPParameterSpec.
 */
public class OAEPParameters extends AlgorithmParametersSpi {

    private String mdName;
    private String mgfName;
    private String mgfMdName;
    private byte[] pSrc;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof OAEPParameterSpec oaepSpec)) {
            throw new InvalidParameterSpecException("Unsupported parameter spec: " +
                (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        this.mdName = oaepSpec.getDigestAlgorithm();
        this.mgfName = oaepSpec.getMGFAlgorithm();
        if (oaepSpec.getMGFParameters() instanceof MGF1ParameterSpec mgf1Spec) {
            this.mgfMdName = mgf1Spec.getDigestAlgorithm();
        } else {
            this.mgfMdName = "SHA-1"; // default
        }
        if (oaepSpec.getPSource() instanceof PSource.PSpecified pSpecified) {
            this.pSrc = pSpecified.getValue().clone();
        } else {
            this.pSrc = new byte[0];
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // Parse ASN.1 DER encoded OAEP parameters
        // For simplicity, set defaults - full ASN.1 parsing would be complex
        // RSAES-OAEP-params ::= SEQUENCE {
        //     hashAlgorithm    [0] HashAlgorithm    DEFAULT sha1,
        //     maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
        //     pSourceAlgorithm [2] PSourceAlgorithm DEFAULT pSpecifiedEmpty
        // }
        try {
            parseDER(params);
        } catch (Exception e) {
            // Default to SHA-1 if parsing fails
            this.mdName = "SHA-1";
            this.mgfName = "MGF1";
            this.mgfMdName = "SHA-1";
            this.pSrc = new byte[0];
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
        if (paramSpec.isAssignableFrom(OAEPParameterSpec.class)) {
            if (mdName == null) {
                throw new InvalidParameterSpecException("OAEP parameters not initialized");
            }
            return (T) new OAEPParameterSpec(
                mdName,
                mgfName,
                new MGF1ParameterSpec(mgfMdName),
                (pSrc != null && pSrc.length > 0) ? new PSource.PSpecified(pSrc) : PSource.PSpecified.DEFAULT
            );
        }
        throw new InvalidParameterSpecException("Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        if (mdName == null) {
            throw new IOException("OAEP parameters not initialized");
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
        if (mdName != null) {
            return "OAEP Parameters: hash=" + mdName + ", mgf=" + mgfName + "(" + mgfMdName + ")";
        }
        return "OAEP Parameters: <not initialized>";
    }

    private void parseDER(byte[] der) throws IOException {
        // Set defaults
        this.mdName = "SHA-1";
        this.mgfName = "MGF1";
        this.mgfMdName = "SHA-1";
        this.pSrc = new byte[0];

        if (der == null || der.length < 2) {
            return; // use defaults
        }

        int[] offset = {0};

        // Expect SEQUENCE
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE tag");
        }
        int seqLen = readLength(der, offset);
        int seqEnd = offset[0] + seqLen;

        // Parse optional tagged components
        while (offset[0] < seqEnd) {
            int tag = der[offset[0]++] & 0xFF;
            int len = readLength(der, offset);

            if ((tag & 0xA0) == 0xA0) { // context-specific tag
                int tagNum = tag & 0x1F;
                switch (tagNum) {
                    case 0: // hashAlgorithm
                        this.mdName = parseAlgorithmIdentifier(der, offset, len);
                        break;
                    case 1: // maskGenAlgorithm
                        parseMGFAlgorithm(der, offset, len);
                        break;
                    case 2: // pSourceAlgorithm
                        // Skip for now, use default
                        offset[0] += len;
                        break;
                    default:
                        offset[0] += len;
                }
            } else {
                offset[0] += len;
            }
        }
    }

    private String parseAlgorithmIdentifier(byte[] der, int[] offset, int len) throws IOException {
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
        int startOffset = offset[0];
        if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE in AlgorithmIdentifier");
        }
        readLength(der, offset);

        // Read OID
        if (der[offset[0]++] != 0x06) {
            throw new IOException("Expected OID in AlgorithmIdentifier");
        }
        int oidLen = readLength(der, offset);
        String oid = parseOID(der, offset[0], oidLen);
        offset[0] = startOffset + len;

        return oidToDigestName(oid);
    }

    private void parseMGFAlgorithm(byte[] der, int[] offset, int len) throws IOException {
        int startOffset = offset[0];
        // For MGF1, the parameters contain the hash algorithm
        this.mgfName = "MGF1";
        // Skip to end for now
        offset[0] = startOffset + len;
    }

    private String parseOID(byte[] der, int offset, int len) {
        StringBuilder oid = new StringBuilder();
        int firstByte = der[offset] & 0xFF;
        oid.append(firstByte / 40).append('.').append(firstByte % 40);

        long value = 0;
        for (int i = 1; i < len; i++) {
            int b = der[offset + i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }
        return oid.toString();
    }

    private String oidToDigestName(String oid) {
        return switch (oid) {
            case "1.3.14.3.2.26" -> "SHA-1";
            case "2.16.840.1.101.3.4.2.1" -> "SHA-256";
            case "2.16.840.1.101.3.4.2.2" -> "SHA-384";
            case "2.16.840.1.101.3.4.2.3" -> "SHA-512";
            case "2.16.840.1.101.3.4.2.4" -> "SHA-224";
            default -> "SHA-1";
        };
    }

    private int readLength(byte[] der, int[] offset) {
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

    private byte[] encodeDER() throws IOException {
        // For simplicity, encode basic parameters
        // This is a simplified encoding
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

        // Encode hash algorithm [0]
        byte[] hashOid = digestNameToOID(mdName);
        byte[] hashAlgId = encodeAlgorithmIdentifier(hashOid);
        byte[] hashTagged = encodeContextSpecific(0, hashAlgId);

        // Encode MGF algorithm [1]
        byte[] mgfHashOid = digestNameToOID(mgfMdName);
        byte[] mgfHashAlgId = encodeAlgorithmIdentifier(mgfHashOid);
        byte[] mgf1Oid = new byte[]{0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x08}; // 1.2.840.113549.1.1.8
        byte[] mgfAlgId = encodeAlgorithmIdentifierWithParams(mgf1Oid, mgfHashAlgId);
        byte[] mgfTagged = encodeContextSpecific(1, mgfAlgId);

        int contentLen = hashTagged.length + mgfTagged.length;
        baos.write(0x30); // SEQUENCE
        baos.write(contentLen);
        baos.write(hashTagged);
        baos.write(mgfTagged);

        return baos.toByteArray();
    }

    private byte[] digestNameToOID(String name) {
        return switch (name) {
            case "SHA-1", "SHA1" -> new byte[]{0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A};
            case "SHA-256", "SHA256" -> new byte[]{0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
            case "SHA-384", "SHA384" -> new byte[]{0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
            case "SHA-512", "SHA512" -> new byte[]{0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
            case "SHA-224", "SHA224" -> new byte[]{0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04};
            default -> new byte[]{0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A}; // SHA-1
        };
    }

    private byte[] encodeAlgorithmIdentifier(byte[] oid) {
        // AlgorithmIdentifier with NULL parameters
        byte[] nullParams = new byte[]{0x05, 0x00};
        byte[] result = new byte[2 + oid.length + nullParams.length];
        result[0] = 0x30;
        result[1] = (byte)(oid.length + nullParams.length);
        System.arraycopy(oid, 0, result, 2, oid.length);
        System.arraycopy(nullParams, 0, result, 2 + oid.length, nullParams.length);
        return result;
    }

    private byte[] encodeAlgorithmIdentifierWithParams(byte[] oid, byte[] params) {
        byte[] result = new byte[2 + oid.length + params.length];
        result[0] = 0x30;
        result[1] = (byte)(oid.length + params.length);
        System.arraycopy(oid, 0, result, 2, oid.length);
        System.arraycopy(params, 0, result, 2 + oid.length, params.length);
        return result;
    }

    private byte[] encodeContextSpecific(int tag, byte[] content) {
        byte[] result = new byte[2 + content.length];
        result[0] = (byte)(0xA0 | tag);
        result[1] = (byte)content.length;
        System.arraycopy(content, 0, result, 2, content.length);
        return result;
    }
}
