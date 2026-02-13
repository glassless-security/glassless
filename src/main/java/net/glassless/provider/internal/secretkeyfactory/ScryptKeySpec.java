package net.glassless.provider.internal.secretkeyfactory;

import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Key specification for SCRYPT key derivation.
 *
 * SCRYPT parameters:
 * - password: the password
 * - salt: the salt (should be at least 16 bytes)
 * - costParameter (N): CPU/memory cost parameter, must be power of 2
 * - blockSize (r): block size parameter
 * - parallelization (p): parallelization parameter
 * - keyLength: desired key length in bits
 */
public class ScryptKeySpec implements KeySpec {

    private final char[] password;
    private final byte[] salt;
    private final int costParameter;      // N
    private final int blockSize;          // r
    private final int parallelization;    // p
    private final int keyLength;          // in bits

    /**
     * Creates a ScryptKeySpec with all parameters.
     *
     * @param password the password
     * @param salt the salt (recommended at least 16 bytes)
     * @param costParameter N - CPU/memory cost, must be power of 2 and > 1
     * @param blockSize r - block size, typically 8
     * @param parallelization p - parallelization factor, typically 1
     * @param keyLength desired key length in bits
     */
    public ScryptKeySpec(char[] password, byte[] salt, int costParameter,
                         int blockSize, int parallelization, int keyLength) {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        if (salt == null) {
            throw new IllegalArgumentException("Salt cannot be null");
        }
        if (costParameter <= 1 || (costParameter & (costParameter - 1)) != 0) {
            throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
        }
        if (blockSize < 1) {
            throw new IllegalArgumentException("Block size r must be >= 1");
        }
        if (parallelization < 1) {
            throw new IllegalArgumentException("Parallelization p must be >= 1");
        }
        if (keyLength <= 0) {
            throw new IllegalArgumentException("Key length must be positive");
        }

        this.password = password.clone();
        this.salt = salt.clone();
        this.costParameter = costParameter;
        this.blockSize = blockSize;
        this.parallelization = parallelization;
        this.keyLength = keyLength;
    }

    /**
     * Creates a ScryptKeySpec with common defaults (r=8, p=1).
     *
     * @param password the password
     * @param salt the salt
     * @param costParameter N - CPU/memory cost
     * @param keyLength desired key length in bits
     */
    public ScryptKeySpec(char[] password, byte[] salt, int costParameter, int keyLength) {
        this(password, salt, costParameter, 8, 1, keyLength);
    }

    public char[] getPassword() {
        return password.clone();
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public int getCostParameter() {
        return costParameter;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public int getParallelization() {
        return parallelization;
    }

    public int getKeyLength() {
        return keyLength;
    }

    /**
     * Clears the password from memory.
     */
    public void clearPassword() {
        Arrays.fill(password, '\0');
    }
}
