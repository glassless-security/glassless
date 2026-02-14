package net.glassless.provider.internal.mlkem;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Base KEMSpi implementation for ML-KEM.
 * Implements the Key Encapsulation Mechanism as defined in FIPS 203.
 */
public class MLKEM implements KEMSpi {

    protected final String opensslName;
    protected final String jcaAlgorithm;
    protected final int sharedSecretSize;

    public MLKEM() {
        this("mlkem768", "ML-KEM-768", 32);
    }

    protected MLKEM(String opensslName, String jcaAlgorithm, int sharedSecretSize) {
        this.opensslName = opensslName;
        this.jcaAlgorithm = jcaAlgorithm;
        this.sharedSecretSize = sharedSecretSize;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                                                  SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (publicKey == null) {
            throw new InvalidKeyException("Public key cannot be null");
        }
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not supported for ML-KEM");
        }

        byte[] encodedKey = publicKey.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("Public key encoding is null");
        }

        return new MLKEMEncapsulator(encodedKey, sharedSecretSize);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("Private key cannot be null");
        }
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not supported for ML-KEM");
        }

        byte[] encodedKey = privateKey.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("Private key encoding is null");
        }

        return new MLKEMDecapsulator(encodedKey, sharedSecretSize);
    }

    /**
     * Encapsulator implementation for ML-KEM.
     */
    private static class MLKEMEncapsulator implements EncapsulatorSpi {
        private final byte[] publicKeyEncoded;
        private final int sharedSecretSize;
        private int encapsulationSize = -1;

        MLKEMEncapsulator(byte[] publicKeyEncoded, int sharedSecretSize) {
            this.publicKeyEncoded = publicKeyEncoded;
            this.sharedSecretSize = sharedSecretSize;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            if (from < 0 || from > to || to > sharedSecretSize) {
                throw new IllegalArgumentException("Invalid range: from=" + from + ", to=" + to);
            }

            try (Arena arena = Arena.ofConfined()) {
                // Load the public key
                MemorySegment pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded, arena);
                if (pkey == null || pkey.address() == 0) {
                    throw new ProviderException("Failed to load public key");
                }

                try {
                    // Create context for encapsulation
                    MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
                        MemorySegment.NULL, pkey, MemorySegment.NULL);
                    if (ctx == null || ctx.address() == 0) {
                        throw new ProviderException("Failed to create EVP_PKEY_CTX");
                    }

                    try {
                        // Initialize for encapsulation
                        int result = OpenSSLCrypto.EVP_PKEY_encapsulate_init(ctx, MemorySegment.NULL);
                        if (result != 1) {
                            throw new ProviderException("EVP_PKEY_encapsulate_init failed");
                        }

                        // Get required sizes
                        MemorySegment wrappedLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
                        MemorySegment secretLenPtr = arena.allocate(ValueLayout.JAVA_LONG);

                        result = OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, MemorySegment.NULL, wrappedLenPtr,
                            MemorySegment.NULL, secretLenPtr);
                        if (result != 1) {
                            throw new ProviderException("EVP_PKEY_encapsulate (get size) failed");
                        }

                        long wrappedLen = wrappedLenPtr.get(ValueLayout.JAVA_LONG, 0);
                        long secretLen = secretLenPtr.get(ValueLayout.JAVA_LONG, 0);

                        // Allocate buffers
                        MemorySegment wrappedBuffer = arena.allocate(ValueLayout.JAVA_BYTE, wrappedLen);
                        MemorySegment secretBuffer = arena.allocate(ValueLayout.JAVA_BYTE, secretLen);

                        // Perform encapsulation
                        result = OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, wrappedBuffer, wrappedLenPtr,
                            secretBuffer, secretLenPtr);
                        if (result != 1) {
                            throw new ProviderException("EVP_PKEY_encapsulate failed");
                        }

                        // Extract results
                        byte[] ciphertext = new byte[(int) wrappedLenPtr.get(ValueLayout.JAVA_LONG, 0)];
                        wrappedBuffer.asByteBuffer().get(ciphertext);

                        byte[] fullSecret = new byte[(int) secretLenPtr.get(ValueLayout.JAVA_LONG, 0)];
                        secretBuffer.asByteBuffer().get(fullSecret);

                        // Create secret key from specified range
                        byte[] keyBytes = new byte[to - from];
                        System.arraycopy(fullSecret, from, keyBytes, 0, keyBytes.length);
                        String keyAlgorithm = algorithm != null ? algorithm : "Generic";
                        SecretKey secretKey = new SecretKeySpec(keyBytes, keyAlgorithm);

                        // Store encapsulation size
                        encapsulationSize = ciphertext.length;

                        return new KEM.Encapsulated(secretKey, ciphertext, null);
                    } finally {
                        OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
                    }
                } finally {
                    OpenSSLCrypto.EVP_PKEY_free(pkey);
                }
            } catch (ProviderException e) {
                throw e;
            } catch (Throwable e) {
                throw new ProviderException("ML-KEM encapsulation failed", e);
            }
        }

        @Override
        public int engineSecretSize() {
            return sharedSecretSize;
        }

        @Override
        public int engineEncapsulationSize() {
            if (encapsulationSize < 0) {
                // Calculate by doing a dummy encapsulation to get the size
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment pkey = OpenSSLCrypto.loadPublicKey(publicKeyEncoded, arena);
                    if (pkey != null && pkey.address() != 0) {
                        try {
                            MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
                                MemorySegment.NULL, pkey, MemorySegment.NULL);
                            if (ctx != null && ctx.address() != 0) {
                                try {
                                    if (OpenSSLCrypto.EVP_PKEY_encapsulate_init(ctx, MemorySegment.NULL) == 1) {
                                        MemorySegment wrappedLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
                                        MemorySegment secretLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
                                        if (OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, MemorySegment.NULL, wrappedLenPtr,
                                            MemorySegment.NULL, secretLenPtr) == 1) {
                                            encapsulationSize = (int) wrappedLenPtr.get(ValueLayout.JAVA_LONG, 0);
                                        }
                                    }
                                } finally {
                                    OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
                                }
                            }
                        } finally {
                            OpenSSLCrypto.EVP_PKEY_free(pkey);
                        }
                    }
                } catch (Throwable e) {
                    // Ignore
                }
            }
            return encapsulationSize > 0 ? encapsulationSize : 0;
        }
    }

    /**
     * Decapsulator implementation for ML-KEM.
     */
    private static class MLKEMDecapsulator implements DecapsulatorSpi {
        private final byte[] privateKeyEncoded;
        private final int sharedSecretSize;
        private int encapsulationSize = -1;

        MLKEMDecapsulator(byte[] privateKeyEncoded, int sharedSecretSize) {
            this.privateKeyEncoded = privateKeyEncoded;
            this.sharedSecretSize = sharedSecretSize;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            if (encapsulation == null) {
                throw new DecapsulateException("Encapsulation cannot be null");
            }
            if (from < 0 || from > to || to > sharedSecretSize) {
                throw new IllegalArgumentException("Invalid range: from=" + from + ", to=" + to);
            }

            try (Arena arena = Arena.ofConfined()) {
                // Load the private key
                MemorySegment pkey = OpenSSLCrypto.loadPrivateKey(0, privateKeyEncoded, arena);
                if (pkey == null || pkey.address() == 0) {
                    throw new DecapsulateException("Failed to load private key");
                }

                try {
                    // Create context for decapsulation
                    MemorySegment ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
                        MemorySegment.NULL, pkey, MemorySegment.NULL);
                    if (ctx == null || ctx.address() == 0) {
                        throw new DecapsulateException("Failed to create EVP_PKEY_CTX");
                    }

                    try {
                        // Initialize for decapsulation
                        int result = OpenSSLCrypto.EVP_PKEY_decapsulate_init(ctx, MemorySegment.NULL);
                        if (result != 1) {
                            throw new DecapsulateException("EVP_PKEY_decapsulate_init failed");
                        }

                        // Prepare encapsulation buffer
                        MemorySegment wrappedBuffer = arena.allocate(ValueLayout.JAVA_BYTE, encapsulation.length);
                        wrappedBuffer.asByteBuffer().put(encapsulation);

                        // Get required size
                        MemorySegment secretLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
                        result = OpenSSLCrypto.EVP_PKEY_decapsulate(ctx, MemorySegment.NULL, secretLenPtr,
                            wrappedBuffer, encapsulation.length);
                        if (result != 1) {
                            throw new DecapsulateException("EVP_PKEY_decapsulate (get size) failed");
                        }

                        long secretLen = secretLenPtr.get(ValueLayout.JAVA_LONG, 0);
                        MemorySegment secretBuffer = arena.allocate(ValueLayout.JAVA_BYTE, secretLen);

                        // Perform decapsulation
                        result = OpenSSLCrypto.EVP_PKEY_decapsulate(ctx, secretBuffer, secretLenPtr,
                            wrappedBuffer, encapsulation.length);
                        if (result != 1) {
                            throw new DecapsulateException("EVP_PKEY_decapsulate failed");
                        }

                        // Extract result
                        byte[] fullSecret = new byte[(int) secretLenPtr.get(ValueLayout.JAVA_LONG, 0)];
                        secretBuffer.asByteBuffer().get(fullSecret);

                        // Create secret key from specified range
                        byte[] keyBytes = new byte[to - from];
                        System.arraycopy(fullSecret, from, keyBytes, 0, keyBytes.length);
                        String keyAlgorithm = algorithm != null ? algorithm : "Generic";
                        return new SecretKeySpec(keyBytes, keyAlgorithm);
                    } finally {
                        OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
                    }
                } finally {
                    OpenSSLCrypto.EVP_PKEY_free(pkey);
                }
            } catch (DecapsulateException e) {
                throw e;
            } catch (Throwable e) {
                throw new DecapsulateException("ML-KEM decapsulation failed", e);
            }
        }

        @Override
        public int engineSecretSize() {
            return sharedSecretSize;
        }

        @Override
        public int engineEncapsulationSize() {
            if (encapsulationSize < 0) {
                // ML-KEM ciphertext sizes:
                // ML-KEM-512: 768 bytes
                // ML-KEM-768: 1088 bytes
                // ML-KEM-1024: 1568 bytes
                // We'll estimate based on key size for now
                encapsulationSize = 1088; // Default to 768 variant
            }
            return encapsulationSize;
        }
    }
}
