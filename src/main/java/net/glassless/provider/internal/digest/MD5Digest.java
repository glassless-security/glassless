package net.glassless.provider.internal.digest;

/**
 * MD5 message digest implementation.
 * Digest size: 128 bits (16 bytes)
 */
public class MD5Digest extends SHADigest {

    public MD5Digest() {
        super("md5");
    }
}
