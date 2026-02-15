package net.glassless.provider.internal.hybridkem;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * Private key implementation for hybrid KEM algorithms.
 * Since hybrid KEMs don't have standard ASN.1 encoders yet, we use a custom format:
 * - 4 bytes: magic header "HKEM"
 * - 2 bytes: format version (1)
 * - UTF string: OpenSSL algorithm name
 * - byte array: raw private key
 */
public class GlaSSLessHybridKEMPrivateKey implements PrivateKey, Destroyable {

   private static final byte[] MAGIC = {'H', 'K', 'E', 'M'};
   private static final short VERSION = 1;

   private final String algorithm;
   private final String opensslName;
   private byte[] rawKey;
   private boolean destroyed = false;

   public GlaSSLessHybridKEMPrivateKey(String algorithm, String opensslName, byte[] rawKey) {
      this.algorithm = algorithm;
      this.opensslName = opensslName;
      this.rawKey = rawKey.clone();
   }

   /**
    * Decode from the custom format.
    */
   public static GlaSSLessHybridKEMPrivateKey decode(byte[] encoded) throws IOException {
      try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encoded))) {
         // Check magic
         byte[] magic = new byte[4];
         dis.readFully(magic);
         if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Invalid hybrid KEM private key format");
         }

         // Check version
         short version = dis.readShort();
         if (version != VERSION) {
            throw new IOException("Unsupported hybrid KEM key version: " + version);
         }

         // Read algorithm names
         String opensslName = dis.readUTF();
         String algorithm = dis.readUTF();

         // Read raw key
         int keyLen = dis.readInt();
         byte[] rawKey = new byte[keyLen];
         dis.readFully(rawKey);

         return new GlaSSLessHybridKEMPrivateKey(algorithm, opensslName, rawKey);
      }
   }

   @Override
   public String getAlgorithm() {
      return algorithm;
   }

   /**
    * Returns the OpenSSL algorithm name (e.g., "X25519MLKEM768").
    */
   public String getOpenSSLName() {
      return opensslName;
   }

   /**
    * Returns the raw private key bytes.
    */
   public byte[] getRawKey() {
      if (destroyed) {
         throw new IllegalStateException("Key has been destroyed");
      }
      return rawKey.clone();
   }

   @Override
   public String getFormat() {
      return "RAW";
   }

   @Override
   public byte[] getEncoded() {
      if (destroyed) {
         throw new IllegalStateException("Key has been destroyed");
      }
      try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
           DataOutputStream dos = new DataOutputStream(baos)) {
         dos.write(MAGIC);
         dos.writeShort(VERSION);
         dos.writeUTF(opensslName);
         dos.writeUTF(algorithm);
         dos.writeInt(rawKey.length);
         dos.write(rawKey);
         return baos.toByteArray();
      } catch (IOException e) {
         throw new RuntimeException("Failed to encode hybrid KEM private key", e);
      }
   }

   @Override
   public void destroy() throws DestroyFailedException {
      if (!destroyed && rawKey != null) {
         Arrays.fill(rawKey, (byte) 0);
         rawKey = null;
         destroyed = true;
      }
   }

   @Override
   public boolean isDestroyed() {
      return destroyed;
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof GlaSSLessHybridKEMPrivateKey other)) return false;
      if (destroyed || other.destroyed) return false;
      return algorithm.equals(other.algorithm) &&
             opensslName.equals(other.opensslName) &&
             Arrays.equals(rawKey, other.rawKey);
   }

   @Override
   public int hashCode() {
      if (destroyed) return 0;
      int result = algorithm.hashCode();
      result = 31 * result + opensslName.hashCode();
      result = 31 * result + Arrays.hashCode(rawKey);
      return result;
   }
}
