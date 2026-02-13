package net.glassless.provider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Detects and reports FIPS 140 compliance mode status.
 *
 * <p>FIPS mode can be detected through multiple mechanisms:
 * <ul>
 *   <li>OpenSSL FIPS provider being enabled as default</li>
 *   <li>OpenSSL FIPS provider being available</li>
 *   <li>System crypto policy set to FIPS (RHEL/Fedora)</li>
 *   <li>Java system property {@code glassless.fips.mode}</li>
 * </ul>
 *
 * <p>When FIPS mode is enabled, only FIPS 140-2/140-3 approved algorithms
 * are available, and some algorithms have minimum key length requirements.
 */
public final class FIPSStatus {

    private static final String FIPS_MODE_PROPERTY = "glassless.fips.mode";
    private static final String CRYPTO_POLICIES_STATE_FILE = "/etc/crypto-policies/state/current";

    private static volatile Boolean cachedFIPSMode = null;

    private FIPSStatus() {
        // Utility class
    }

    /**
     * Returns whether FIPS mode is currently enabled.
     *
     * <p>This method checks multiple sources in the following order:
     * <ol>
     *   <li>Java system property {@code glassless.fips.mode} (if set to "true" or "false")</li>
     *   <li>OpenSSL default properties FIPS flag</li>
     *   <li>System crypto policy (on RHEL/Fedora)</li>
     * </ol>
     *
     * <p>The result is cached after the first call for performance.
     *
     * @return true if FIPS mode is enabled, false otherwise
     */
    public static boolean isFIPSEnabled() {
        if (cachedFIPSMode != null) {
            return cachedFIPSMode;
        }

        synchronized (FIPSStatus.class) {
            if (cachedFIPSMode != null) {
                return cachedFIPSMode;
            }

            cachedFIPSMode = detectFIPSMode();
            return cachedFIPSMode;
        }
    }

    /**
     * Detects FIPS mode through various mechanisms.
     */
    private static boolean detectFIPSMode() {
        // 1. Check Java system property first (allows override)
        String propertyValue = System.getProperty(FIPS_MODE_PROPERTY);
        if (propertyValue != null) {
            if ("true".equalsIgnoreCase(propertyValue)) {
                return true;
            } else if ("false".equalsIgnoreCase(propertyValue)) {
                return false;
            }
            // Invalid value, continue with other checks
        }

        // 2. Check OpenSSL FIPS mode
        if (OpenSSLCrypto.isFIPSEnabled()) {
            return true;
        }

        // 3. Check system crypto policy (RHEL/Fedora)
        if (isSystemCryptoPolicyFIPS()) {
            return true;
        }

        return false;
    }

    /**
     * Checks if the system crypto policy is set to FIPS.
     * This is specific to RHEL/Fedora systems that use crypto-policies.
     */
    private static boolean isSystemCryptoPolicyFIPS() {
        try {
            Path policyFile = Path.of(CRYPTO_POLICIES_STATE_FILE);
            if (Files.exists(policyFile)) {
                String policy = Files.readString(policyFile).trim();
                return policy.equalsIgnoreCase("FIPS") || policy.startsWith("FIPS:");
            }
        } catch (IOException | SecurityException e) {
            // Ignore - file not accessible
        }
        return false;
    }

    /**
     * Returns whether the OpenSSL FIPS provider is available.
     *
     * @return true if the FIPS provider is available, false otherwise
     */
    public static boolean isFIPSProviderAvailable() {
        return OpenSSLCrypto.isFIPSProviderAvailable();
    }

    /**
     * Clears the cached FIPS mode status.
     * This is primarily useful for testing.
     */
    public static void clearCache() {
        synchronized (FIPSStatus.class) {
            cachedFIPSMode = null;
        }
    }

    /**
     * Returns a human-readable description of the current FIPS status.
     *
     * @return status description string
     */
    public static String getStatusDescription() {
        StringBuilder sb = new StringBuilder();
        sb.append("FIPS Mode: ").append(isFIPSEnabled() ? "ENABLED" : "DISABLED");
        sb.append("\n  OpenSSL FIPS enabled: ").append(OpenSSLCrypto.isFIPSEnabled());
        sb.append("\n  FIPS provider available: ").append(isFIPSProviderAvailable());
        sb.append("\n  System crypto policy FIPS: ").append(isSystemCryptoPolicyFIPS());

        String prop = System.getProperty(FIPS_MODE_PROPERTY);
        if (prop != null) {
            sb.append("\n  System property override: ").append(prop);
        }

        return sb.toString();
    }
}
