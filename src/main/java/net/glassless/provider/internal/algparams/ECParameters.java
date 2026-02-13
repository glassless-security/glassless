package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * AlgorithmParameters implementation for EC (Elliptic Curve).
 * Supports ECParameterSpec and ECGenParameterSpec.
 */
public class ECParameters extends AlgorithmParametersSpi {

    private String curveName;
    private ECParameterSpec ecParameterSpec;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec instanceof ECGenParameterSpec ecGenSpec) {
            this.curveName = ecGenSpec.getName();
            this.ecParameterSpec = null;
        } else if (paramSpec instanceof ECParameterSpec ecSpec) {
            this.ecParameterSpec = ecSpec;
            this.curveName = getCurveNameFromSpec(ecSpec);
        } else {
            throw new InvalidParameterSpecException("Unsupported parameter spec: " +
                (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // Parse ASN.1 DER encoded EC parameters
        // For simplicity, we support named curves encoded as OID
        try {
            String oid = parseOIDFromDER(params);
            this.curveName = oidToCurveName(oid);
            this.ecParameterSpec = null;
        } catch (Exception e) {
            throw new IOException("Failed to parse EC parameters", e);
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
        if (paramSpec.isAssignableFrom(ECGenParameterSpec.class)) {
            if (curveName != null) {
                return (T) new ECGenParameterSpec(curveName);
            }
            throw new InvalidParameterSpecException("Curve name not available");
        } else if (paramSpec.isAssignableFrom(ECParameterSpec.class)) {
            if (ecParameterSpec != null) {
                return (T) ecParameterSpec;
            }
            throw new InvalidParameterSpecException("ECParameterSpec not available");
        }
        throw new InvalidParameterSpecException("Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        if (curveName == null) {
            throw new IOException("No curve name available for encoding");
        }
        String oid = curveNameToOID(curveName);
        return encodeOIDToDER(oid);
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
        if (curveName != null) {
            return "EC Parameters: curve=" + curveName;
        } else if (ecParameterSpec != null) {
            return "EC Parameters: " + ecParameterSpec.toString();
        }
        return "EC Parameters: <not initialized>";
    }

    private String getCurveNameFromSpec(ECParameterSpec spec) {
        // Try to determine curve name from field size
        int fieldSize = spec.getCurve().getField().getFieldSize();
        return switch (fieldSize) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            case 224 -> "secp224r1";
            case 192 -> "secp192r1";
            default -> "unknown";
        };
    }

    private String curveNameToOID(String name) {
        return switch (name.toLowerCase()) {
            case "secp256r1", "p-256", "prime256v1" -> "1.2.840.10045.3.1.7";
            case "secp384r1", "p-384" -> "1.3.132.0.34";
            case "secp521r1", "p-521" -> "1.3.132.0.35";
            case "secp224r1", "p-224" -> "1.3.132.0.33";
            case "secp192r1", "p-192", "prime192v1" -> "1.2.840.10045.3.1.1";
            default -> throw new IllegalArgumentException("Unknown curve: " + name);
        };
    }

    private String oidToCurveName(String oid) {
        return switch (oid) {
            case "1.2.840.10045.3.1.7" -> "secp256r1";
            case "1.3.132.0.34" -> "secp384r1";
            case "1.3.132.0.35" -> "secp521r1";
            case "1.3.132.0.33" -> "secp224r1";
            case "1.2.840.10045.3.1.1" -> "secp192r1";
            default -> throw new IllegalArgumentException("Unknown OID: " + oid);
        };
    }

    private String parseOIDFromDER(byte[] der) throws IOException {
        if (der == null || der.length < 2) {
            throw new IOException("Invalid DER encoding");
        }
        // Check for OBJECT IDENTIFIER tag (0x06)
        if (der[0] != 0x06) {
            throw new IOException("Expected OBJECT IDENTIFIER tag");
        }
        int length = der[1] & 0xFF;
        if (der.length < 2 + length) {
            throw new IOException("Invalid DER length");
        }

        // Decode OID
        StringBuilder oid = new StringBuilder();
        int firstByte = der[2] & 0xFF;
        oid.append(firstByte / 40).append('.').append(firstByte % 40);

        long value = 0;
        for (int i = 3; i < 2 + length; i++) {
            int b = der[i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }
        return oid.toString();
    }

    private byte[] encodeOIDToDER(String oid) {
        String[] parts = oid.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid OID: " + oid);
        }

        // Calculate encoded bytes
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

        // First two components are encoded in first byte
        int first = Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]);
        baos.write(first);

        // Encode remaining components
        for (int i = 2; i < parts.length; i++) {
            long value = Long.parseLong(parts[i]);
            encodeOIDComponent(baos, value);
        }

        byte[] oidBytes = baos.toByteArray();
        byte[] result = new byte[2 + oidBytes.length];
        result[0] = 0x06; // OBJECT IDENTIFIER tag
        result[1] = (byte) oidBytes.length;
        System.arraycopy(oidBytes, 0, result, 2, oidBytes.length);
        return result;
    }

    private void encodeOIDComponent(java.io.ByteArrayOutputStream baos, long value) {
        if (value < 128) {
            baos.write((int) value);
        } else {
            // Multi-byte encoding
            int[] bytes = new int[10];
            int count = 0;
            while (value > 0) {
                bytes[count++] = (int) (value & 0x7F);
                value >>= 7;
            }
            for (int i = count - 1; i >= 0; i--) {
                if (i > 0) {
                    baos.write(bytes[i] | 0x80);
                } else {
                    baos.write(bytes[i]);
                }
            }
        }
    }
}
