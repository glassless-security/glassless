package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * AlgorithmParameters implementation for PBE (Password-Based Encryption).
 * Supports PBEParameterSpec containing salt, iteration count, and optional IV.
 * <p>
 * When initialized from DER-encoded PBES2 parameters, this class parses the
 * KDF and encryption scheme OIDs to construct the proper algorithm name
 * (e.g., "PBEWithHmacSHA256AndAES_256"). This is required because
 * {@code AlgorithmId.getName()} for PBES2 calls {@code algParams.toString()}
 * to determine the cipher algorithm name used by PKCS12KeyStore.
 */
public class PBEParameters extends AlgorithmParametersSpi {

   private byte[] salt;
   private int iterationCount;
   private byte[] iv;
   private String algorithmName;
   private byte[] rawDER; // Store original DER for faithful re-encoding

   // PRF (HMAC) OID prefix: 1.2.840.113549.2.*
   private static final byte[] HMAC_OID_PREFIX = {
      0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x02
   };

   // Map final byte of HMAC OID to name
   private static final Map<Integer, String> HMAC_NAMES = Map.of(
      7, "HmacSHA1",
      8, "HmacSHA224",
      9, "HmacSHA256",
      10, "HmacSHA384",
      11, "HmacSHA512",
      12, "HmacSHA512/224",
      13, "HmacSHA512/256"
   );

   // AES-CBC OID prefix: 2.16.840.1.101.3.4.1.*
   private static final byte[] AES_CBC_OID_PREFIX = {
      0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01
   };

   // Map final byte of AES-CBC OID to key size
   private static final Map<Integer, Integer> AES_KEY_SIZES = Map.of(
      2, 128,   // AES-128-CBC
      22, 192,  // AES-192-CBC
      42, 256   // AES-256-CBC
   );

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
      if (rawDER != null) {
         return rawDER.clone();
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
      if (algorithmName != null) {
         return algorithmName;
      }
      if (salt != null) {
         return "PBE Parameters: salt length=" + salt.length + " bytes, iterations=" + iterationCount +
            (iv != null ? ", IV length=" + iv.length + " bytes" : "");
      }
      return "PBE Parameters: <not initialized>";
   }

   private void parseDER(byte[] der) throws IOException {
      this.rawDER = der.clone();
      int[] offset = {0};

      // Expect SEQUENCE (PBES2-params)
      if (der[offset[0]++] != 0x30) {
         throw new IOException("Expected SEQUENCE tag");
      }
      int seqLen = readLength(der, offset);
      int seqEnd = offset[0] + seqLen;

      // Before JDK-8202837, PBES2-params was mistakenly encoded like an
      // AlgorithmId (OID + real params). If the first element is an OID
      // instead of a SEQUENCE, skip the OID and re-parse the next SEQUENCE
      // as the real PBES2-params.
      if (der[offset[0]] == 0x06) {
         // Skip the erroneous OID
         offset[0]++;
         int oidLen = readLength(der, offset);
         offset[0] += oidLen;
         // The next element should be the real PBES2-params SEQUENCE
         if (der[offset[0]++] != 0x30) {
            throw new IOException("Expected SEQUENCE after OID in legacy PBES2 encoding");
         }
         seqLen = readLength(der, offset);
         seqEnd = offset[0] + seqLen;
      }

      // Parse keyDerivationFunc (AlgorithmIdentifier with PBKDF2-params)
      if (der[offset[0]++] != 0x30) {
         throw new IOException("Expected SEQUENCE for keyDerivationFunc");
      }
      int kdfLen = readLength(der, offset);
      int kdfEnd = offset[0] + kdfLen;

      // Parse KDF OID
      if (der[offset[0]++] != 0x06) {
         throw new IOException("Expected OID");
      }
      int oidLen = readLength(der, offset);
      // Skip KDF OID (PBKDF2)
      offset[0] += oidLen;

      // Parse PBKDF2-params
      if (der[offset[0]++] != 0x30) {
         throw new IOException("Expected SEQUENCE for PBKDF2-params");
      }
      int pbkdf2ParamsLen = readLength(der, offset);
      int pbkdf2ParamsEnd = offset[0] + pbkdf2ParamsLen;

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

      // Skip optional keyLength INTEGER
      if (offset[0] < pbkdf2ParamsEnd && der[offset[0]] == 0x02) {
         offset[0]++;
         int keyLenLen = readLength(der, offset);
         offset[0] += keyLenLen;
      }

      // Parse optional PRF AlgorithmIdentifier to determine HMAC algorithm
      String hmacName = "HmacSHA1"; // default per RFC 8018
      if (offset[0] < pbkdf2ParamsEnd && der[offset[0]] == 0x30) {
         offset[0]++;
         int prfLen = readLength(der, offset);
         int prfEnd = offset[0] + prfLen;
         if (der[offset[0]] == 0x06) {
            offset[0]++;
            int prfOidLen = readLength(der, offset);
            byte[] prfOid = new byte[prfOidLen];
            System.arraycopy(der, offset[0], prfOid, 0, prfOidLen);
            hmacName = resolveHmacName(prfOid);
         }
         offset[0] = prfEnd;
      }

      // Skip to encryptionScheme
      offset[0] = kdfEnd;

      // Parse encryptionScheme (AlgorithmIdentifier)
      String cipherName = null;
      if (offset[0] < seqEnd && der[offset[0]] == 0x30) {
         offset[0]++;
         int encLen = readLength(der, offset);
         int encEnd = offset[0] + encLen;

         // Parse encryption algorithm OID
         if (der[offset[0]++] != 0x06) {
            throw new IOException("Expected OID for encryption algorithm");
         }
         int encOidLen = readLength(der, offset);
         byte[] encOid = new byte[encOidLen];
         System.arraycopy(der, offset[0], encOid, 0, encOidLen);
         offset[0] += encOidLen;
         cipherName = resolveCipherName(encOid);

         // Parse IV if present
         if (offset[0] < encEnd && der[offset[0]] == 0x04) {
            offset[0]++;
            int ivLen = readLength(der, offset);
            this.iv = new byte[ivLen];
            System.arraycopy(der, offset[0], this.iv, 0, ivLen);
         }
      }

      // Construct the algorithm name
      if (cipherName != null) {
         this.algorithmName = "PBEWith" + hmacName + "And" + cipherName;
      }
   }

   /**
    * Resolves the HMAC algorithm name from a PRF OID.
    */
   private String resolveHmacName(byte[] oid) {
      if (oid.length == HMAC_OID_PREFIX.length + 1 &&
          startsWith(oid, HMAC_OID_PREFIX)) {
         String name = HMAC_NAMES.get(oid[oid.length - 1] & 0xFF);
         if (name != null) {
            return name;
         }
      }
      return "HmacSHA1"; // fallback to default
   }

   /**
    * Resolves the cipher algorithm name (e.g., "AES_256") from an encryption OID.
    */
   private String resolveCipherName(byte[] oid) {
      if (oid.length == AES_CBC_OID_PREFIX.length + 1 &&
          startsWith(oid, AES_CBC_OID_PREFIX)) {
         Integer keySize = AES_KEY_SIZES.get(oid[oid.length - 1] & 0xFF);
         if (keySize != null) {
            return "AES_" + keySize;
         }
      }
      return null;
   }

   private boolean startsWith(byte[] array, byte[] prefix) {
      if (array.length < prefix.length) return false;
      return Arrays.equals(array, 0, prefix.length, prefix, 0, prefix.length);
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
      // Build PBKDF2-params
      byte[] pbkdf2Params = buildPBKDF2Params();

      // Build keyDerivationFunc AlgorithmIdentifier
      byte[] pbkdf2Oid = {0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x05, 0x0C}; // 1.2.840.113549.1.5.12
      byte[] kdfAlgId = encodeSequence(concat(pbkdf2Oid, pbkdf2Params));

      // Build encryptionScheme AlgorithmIdentifier
      byte[] encScheme = buildEncryptionScheme();

      // Build PBES2-params SEQUENCE

      return encodeSequence(concat(kdfAlgId, encScheme));
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
      byte[] aesOid = {0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02};

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
         return new byte[]{0x02, 0x02, (byte) (value >> 8), (byte) value};
      } else if (value < 8388608) {
         return new byte[]{0x02, 0x03, (byte) (value >> 16), (byte) (value >> 8), (byte) value};
      } else {
         return new byte[]{0x02, 0x04, (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
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
