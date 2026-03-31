package net.glassless.provider.internal;

/**
 * Utility methods for ASN.1 DER encoding of public and private keys
 * in X.509 SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo formats.
 */
public final class KeyEncodingUtils {

   private KeyEncodingUtils() {
   }

   /**
    * Creates an X.509 SubjectPublicKeyInfo encoding for a raw public key.
    *
    * @param oid    the DER-encoded OID (e.g., {@code {0x06, 0x03, 0x2B, 0x65, 0x70}} for Ed25519)
    * @param rawKey the raw public key bytes
    * @return the X.509 encoded public key
    */
   public static byte[] createX509Encoding(byte[] oid, byte[] rawKey) {
      // AlgorithmIdentifier: SEQUENCE { OID }
      byte[] algId = new byte[2 + oid.length];
      algId[0] = 0x30;  // SEQUENCE
      algId[1] = (byte) oid.length;
      System.arraycopy(oid, 0, algId, 2, oid.length);

      // BIT STRING { raw key }
      byte[] bitString = new byte[2 + 1 + rawKey.length];
      bitString[0] = 0x03;  // BIT STRING
      bitString[1] = (byte) (1 + rawKey.length);
      bitString[2] = 0x00;  // unused bits
      System.arraycopy(rawKey, 0, bitString, 3, rawKey.length);

      // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
      int totalLen = algId.length + bitString.length;
      byte[] encoded = new byte[2 + totalLen];
      encoded[0] = 0x30;  // SEQUENCE
      encoded[1] = (byte) totalLen;
      System.arraycopy(algId, 0, encoded, 2, algId.length);
      System.arraycopy(bitString, 0, encoded, 2 + algId.length, bitString.length);

      return encoded;
   }

   /**
    * Creates a PKCS#8 PrivateKeyInfo encoding for a raw private key.
    *
    * @param oid      the DER-encoded OID (e.g., {@code {0x06, 0x03, 0x2B, 0x65, 0x70}} for Ed25519)
    * @param keyBytes the raw private key bytes
    * @return the PKCS#8 encoded private key
    */
   public static byte[] createPKCS8Encoding(byte[] oid, byte[] keyBytes) {
      // Version: INTEGER 0
      byte[] version = new byte[]{0x02, 0x01, 0x00};

      // AlgorithmIdentifier: SEQUENCE { OID }
      byte[] algId = new byte[2 + oid.length];
      algId[0] = 0x30;  // SEQUENCE
      algId[1] = (byte) oid.length;
      System.arraycopy(oid, 0, algId, 2, oid.length);

      // Private key: OCTET STRING { OCTET STRING { key bytes } }
      byte[] innerOctet = new byte[2 + keyBytes.length];
      innerOctet[0] = 0x04;  // OCTET STRING
      innerOctet[1] = (byte) keyBytes.length;
      System.arraycopy(keyBytes, 0, innerOctet, 2, keyBytes.length);

      byte[] outerOctet = new byte[2 + innerOctet.length];
      outerOctet[0] = 0x04;  // OCTET STRING
      outerOctet[1] = (byte) innerOctet.length;
      System.arraycopy(innerOctet, 0, outerOctet, 2, innerOctet.length);

      // PrivateKeyInfo: SEQUENCE { version, algorithmIdentifier, privateKey }
      int totalLen = version.length + algId.length + outerOctet.length;
      byte[] encoded = new byte[2 + totalLen];
      encoded[0] = 0x30;  // SEQUENCE
      encoded[1] = (byte) totalLen;
      int offset = 2;
      System.arraycopy(version, 0, encoded, offset, version.length);
      offset += version.length;
      System.arraycopy(algId, 0, encoded, offset, algId.length);
      offset += algId.length;
      System.arraycopy(outerOctet, 0, encoded, offset, outerOctet.length);

      return encoded;
   }
}
