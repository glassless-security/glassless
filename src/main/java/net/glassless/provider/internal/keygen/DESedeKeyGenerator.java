package net.glassless.provider.internal.keygen;

import java.security.ProviderException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Key generator for DESede (Triple DES).
 * DESede uses 168-bit keys (24 bytes with parity bits).
 */
public class DESedeKeyGenerator extends AbstractKeyGenerator {

    public DESedeKeyGenerator() {
        // DESede uses 168-bit key (stored as 192 bits / 24 bytes with parity)
        super("DESede", 168, new int[]{112, 168});
    }

    @Override
    protected SecretKey engineGenerateKey() {
        try {
            // DESede always uses 24 bytes (192 bits) to store the key
            // The effective key strength is 168 bits (or 112 for two-key variant)
            byte[] keyBytes = OpenSSLCrypto.RAND_bytes(24);

            // Set parity bits for each byte (DES requirement)
            setParityBits(keyBytes);

            return new SecretKeySpec(keyBytes, "DESede");
        } catch (Throwable e) {
            throw new ProviderException("Error generating DESede key", e);
        }
    }

    /**
     * Sets the parity bit (LSB) of each byte to make the byte have odd parity.
     * This is required for DES keys.
     */
    private void setParityBits(byte[] key) {
        for (int i = 0; i < key.length; i++) {
            int b = key[i] & 0xFE; // Clear parity bit
            int count = Integer.bitCount(b);
            // Set parity bit to make odd parity
            key[i] = (byte) (b | ((count % 2 == 0) ? 1 : 0));
        }
    }
}
