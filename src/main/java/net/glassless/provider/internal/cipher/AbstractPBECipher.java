package net.glassless.provider.internal.cipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

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
      if (key instanceof PBEKey) {
         password = ((PBEKey) key).getPassword();
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
      AlgorithmParameterSpec ivSpec = null;

      if (params instanceof PBEParameterSpec pbeParams) {
         salt = pbeParams.getSalt();
         iterationCount = pbeParams.getIterationCount();
         ivSpec = pbeParams.getParameterSpec();
      } else {
         throw new InvalidAlgorithmParameterException("PBEParameterSpec required");
      }

      // Build an IvParameterSpec for the parent class
      IvParameterSpec ivParamSpec;
      if (ivSpec instanceof IvParameterSpec) {
         ivParamSpec = (IvParameterSpec) ivSpec;
      } else {
         // Generate random IV if not provided
         byte[] ivBytes = new byte[IV_LENGTH];
         if (random == null) {
            random = new SecureRandom();
         }
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
   protected void reset() {
      super.reset();
      if (derivedKey != null) {
         java.util.Arrays.fill(derivedKey, (byte) 0);
         derivedKey = null;
      }
   }
}
