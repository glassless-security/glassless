package net.glassless.provider.internal.mac;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Abstract base class for HMAC implementations using OpenSSL EVP_MAC API.
 * Extends {@link AbstractMac} with HMAC-specific digest parameter handling.
 */
public abstract class AbstractHmac extends AbstractMac {

   private final String digestName;

   protected AbstractHmac(String digestName, int macLength) {
      super("HMAC", macLength);
      this.digestName = digestName;
   }

   @Override
   protected MemorySegment createParams(Arena arena) {
      return OpenSSLCrypto.createDigestParams(digestName, arena);
   }
}
