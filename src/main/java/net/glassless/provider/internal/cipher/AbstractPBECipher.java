package net.glassless.provider.internal.cipher;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for PBE (Password-Based Encryption) ciphers.
 * Uses PKCS5 PBKDF2 HMAC for key derivation and delegates to the underlying cipher
 * inherited from {@link AbstractCipher}.
 */
abstract class AbstractPBECipher extends AbstractCipher {

   private final int keySize;
   private final String prf; // Pseudo-Random Function (hash algorithm for PBKDF2)
   private byte[] derivedKey;

   // Stored during engineInit for engineGetParameters()
   private byte[] pbeSalt;
   private int pbeIterationCount;

   private static final int IV_LENGTH = 16; // AES block size

   /**
    * Creates a new PBE cipher.
    *
    * @param opensslCipherName the OpenSSL cipher name (e.g., "aes-128-cbc")
    * @param keySize           the key size in bytes
    * @param mode              the cipher mode
    * @param prf               the pseudo-random function for PBKDF2 (e.g., "SHA256", "SHA1")
    */
   protected AbstractPBECipher(String opensslCipherName, int keySize, CipherMode mode, String prf) {
      super(opensslCipherName, mode, CipherPadding.PKCS5PADDING);
      this.keySize = keySize;
      this.prf = prf;
   }

   @Override
   protected void engineSetPadding(String padding) throws NoSuchPaddingException {
      // PBE ciphers typically use PKCS5Padding
      if (!padding.equalsIgnoreCase("PKCS5Padding") && !padding.equalsIgnoreCase("PKCS7Padding")) {
         throw new NoSuchPaddingException("Unsupported padding: " + padding);
      }
   }

   @Override
   protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
      throw new InvalidKeyException("PBE cipher requires PBEParameterSpec");
   }

   @Override
   protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {

      // Extract password from key
      char[] password;
      if (key instanceof PBEKey pbeKey) {
         password = pbeKey.getPassword();
      } else if (key instanceof SecretKey) {
         // Assume the key bytes are the password encoded as UTF-8
         byte[] keyBytes = key.getEncoded();
         password = new String(keyBytes, java.nio.charset.StandardCharsets.UTF_8).toCharArray();
      } else {
         throw new InvalidKeyException("Key must be a PBEKey or SecretKey");
      }

      // Extract salt and iteration count from params
      byte[] salt;
      int iterationCount;
      AlgorithmParameterSpec ivSpec;

      if (params instanceof PBEParameterSpec pbeParams) {
         salt = pbeParams.getSalt();
         iterationCount = pbeParams.getIterationCount();
         ivSpec = pbeParams.getParameterSpec();
      } else {
         throw new InvalidAlgorithmParameterException("PBEParameterSpec required");
      }

      // Store for engineGetParameters()
      this.pbeSalt = salt.clone();
      this.pbeIterationCount = iterationCount;

      // Ensure we have a SecureRandom instance
      if (random == null) {
         random = new SecureRandom();
      }

      // Build an IvParameterSpec for the parent class
      IvParameterSpec ivParamSpec;
      if (ivSpec instanceof IvParameterSpec) {
         ivParamSpec = (IvParameterSpec) ivSpec;
      } else {
         // Generate random IV if not provided
         byte[] ivBytes = new byte[IV_LENGTH];
         random.nextBytes(ivBytes);
         ivParamSpec = new IvParameterSpec(ivBytes);
      }

      try {
         // Derive the key using PBKDF2
         derivedKey = OpenSSLCrypto.PKCS5_PBKDF2_HMAC(password, salt, iterationCount, prf,
            keySize, arena);

         // Create a SecretKey from derived bytes and delegate to parent
         SecretKeySpec derivedSecretKey = new SecretKeySpec(derivedKey, "AES");
         super.engineInit(opmode, derivedSecretKey, ivParamSpec, random);

      } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error initializing PBE cipher", e);
      }
   }

   @Override
   protected AlgorithmParameters engineGetParameters() {
      if (pbeSalt == null) {
         return null;
      }
      try {
         AlgorithmParameters params = AlgorithmParameters.getInstance("PBES2");
         // Initialize from DER so that PBEParameters populates the algorithmName
         // (used by AlgorithmId.getName() via toString() for PBES2)
         byte[] der = buildPBES2DER();
         params.init(der);
         return params;
      } catch (Exception e) {
         throw new ProviderException("Failed to construct PBE parameters", e);
      }
   }

   /**
    * Builds DER-encoded PBES2-params from the current PBE state.
    * Structure: SEQUENCE { keyDerivationFunc, encryptionScheme }
    */
   private byte[] buildPBES2DER() {
      java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

      // --- Build PBKDF2-params ---
      java.io.ByteArrayOutputStream pbkdf2Params = new java.io.ByteArrayOutputStream();
      // Salt OCTET STRING
      writeDERTag(pbkdf2Params, 0x04, pbeSalt);
      // Iteration count INTEGER
      writeDERInteger(pbkdf2Params, pbeIterationCount);
      // Key length INTEGER
      writeDERInteger(pbkdf2Params, keySize);
      // PRF AlgorithmIdentifier
      byte[] prfOid = getPRFOid();
      if (prfOid != null) {
         // SEQUENCE { OID, NULL }
         java.io.ByteArrayOutputStream prfAlgId = new java.io.ByteArrayOutputStream();
         writeDERTag(prfAlgId, 0x06, prfOid);
         prfAlgId.write(0x05); // NULL tag
         prfAlgId.write(0x00); // NULL length
         writeDERTag(pbkdf2Params, 0x30, prfAlgId.toByteArray());
      }
      byte[] pbkdf2ParamsSeq = wrapSequence(pbkdf2Params.toByteArray());

      // --- Build keyDerivationFunc AlgorithmIdentifier ---
      // PBKDF2 OID: 1.2.840.113549.1.5.12
      byte[] pbkdf2OidBytes = {
         0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x05, 0x0C
      };
      java.io.ByteArrayOutputStream kdfAlgId = new java.io.ByteArrayOutputStream();
      writeDERTag(kdfAlgId, 0x06, pbkdf2OidBytes);
      kdfAlgId.write(pbkdf2ParamsSeq, 0, pbkdf2ParamsSeq.length);
      byte[] kdfSeq = wrapSequence(kdfAlgId.toByteArray());

      // --- Build encryptionScheme AlgorithmIdentifier ---
      byte[] encOid = getEncryptionOid();
      java.io.ByteArrayOutputStream encAlgId = new java.io.ByteArrayOutputStream();
      writeDERTag(encAlgId, 0x06, encOid);
      if (iv != null) {
         writeDERTag(encAlgId, 0x04, iv);
      }
      byte[] encSeq = wrapSequence(encAlgId.toByteArray());

      // --- Build PBES2-params SEQUENCE ---
      out.write(kdfSeq, 0, kdfSeq.length);
      out.write(encSeq, 0, encSeq.length);
      return wrapSequence(out.toByteArray());
   }

   private byte[] getPRFOid() {
      // HMAC OID prefix: 1.2.840.113549.2.*
      return switch (prf) {
         case "SHA1" -> new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x02, 0x07};
         case "SHA224" -> new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x02, 0x08};
         case "SHA256" -> new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x02, 0x09};
         case "SHA384" -> new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x02, 0x0A};
         case "SHA512" -> new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x02, 0x0B};
         default -> null;
      };
   }

   private byte[] getEncryptionOid() {
      // AES-CBC OID prefix: 2.16.840.1.101.3.4.1.*
      byte[] prefix = {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01};
      byte suffix = switch (keySize) {
         case 16 -> 0x02;  // AES-128-CBC
         case 24 -> 0x16;  // AES-192-CBC
         case 32 -> 0x2A;  // AES-256-CBC
         default -> 0x02;
      };
      byte[] oid = new byte[prefix.length + 1];
      System.arraycopy(prefix, 0, oid, 0, prefix.length);
      oid[prefix.length] = suffix;
      return oid;
   }

   private static void writeDERTag(java.io.ByteArrayOutputStream out, int tag, byte[] value) {
      out.write(tag);
      writeDERLength(out, value.length);
      out.write(value, 0, value.length);
   }

   private static void writeDERLength(java.io.ByteArrayOutputStream out, int length) {
      if (length < 128) {
         out.write(length);
      } else if (length < 256) {
         out.write(0x81);
         out.write(length);
      } else {
         out.write(0x82);
         out.write(length >> 8);
         out.write(length & 0xFF);
      }
   }

   private static void writeDERInteger(java.io.ByteArrayOutputStream out, int value) {
      out.write(0x02); // INTEGER tag
      if (value < 128) {
         out.write(1);
         out.write(value);
      } else if (value < 256) {
         out.write(2);
         out.write(0);
         out.write(value);
      } else if (value < 32768) {
         out.write(2);
         out.write(value >> 8);
         out.write(value & 0xFF);
      } else if (value < 8388608) {
         out.write(3);
         out.write(value >> 16);
         out.write((value >> 8) & 0xFF);
         out.write(value & 0xFF);
      } else {
         out.write(4);
         out.write((value >> 24) & 0xFF);
         out.write((value >> 16) & 0xFF);
         out.write((value >> 8) & 0xFF);
         out.write(value & 0xFF);
      }
   }

   private static byte[] wrapSequence(byte[] content) {
      java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
      out.write(0x30); // SEQUENCE tag
      writeDERLength(out, content.length);
      out.write(content, 0, content.length);
      return out.toByteArray();
   }

   @Override
   protected AlgorithmParameterSpec extractParameterSpec(AlgorithmParameters params)
      throws InvalidAlgorithmParameterException {
      try {
         return params.getParameterSpec(PBEParameterSpec.class);
      } catch (InvalidParameterSpecException e) {
         throw new InvalidAlgorithmParameterException("Failed to extract PBE parameter spec", e);
      }
   }

   @Override
   protected void reset() {
      super.reset();
      if (derivedKey != null) {
         java.util.Arrays.fill(derivedKey, (byte) 0);
         derivedKey = null;
      }
      // Do NOT clear pbeSalt/pbeIterationCount here:
      // PKCS12KeyStore calls cipher.getParameters() AFTER cipher.doFinal(),
      // and reset() is called at the end of doFinal.
   }
}
