package com.github.yash777.sslautotrust.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Arrays;
import java.util.List;

/**
 * SslAutoTrustProperties
 *
 * <p>All configurable properties for the SSL Auto-Trust starter, bound from
 * {@code application.properties} (or {@code application.yml}) under the
 * {@code ssl.auto-trust.*} prefix.
 *
 * <h3>Default: DISABLED</h3>
 * <pre>
 * # The starter is OFF by default. Enable explicitly:
 * ssl.auto-trust.enabled=true
 *
 * # Or use @EnableSslAutoTrust on any @Configuration class.
 * </pre>
 *
 * <h3>Full configuration reference</h3>
 * <pre>
 * # ── Master switch (DEFAULT: false — explicit opt-in required) ────────────
 * ssl.auto-trust.enabled=true
 *
 * # ── Domain list ─────────────────────────────────────────────────────────
 * # Comma-separated. Accepts full URLs, bare hostnames, or host:port.
 * #   https://host.example.com/any/path   → host + port 443
 * #   host.example.com                    → port 443
 * #   internal.local:8443                 → explicit port
 * ssl.auto-trust.domains=github.com,api.github.com
 *
 * # ── Cert export directory ───────────────────────────────────────────────
 * ssl.auto-trust.export-dir=exportedcerts
 *
 * # ── JKS truststore password (offline inspection only) ──────────────────
 * ssl.auto-trust.truststore-password=changeit
 *
 * # ── Default HTTPS port ──────────────────────────────────────────────────
 * ssl.auto-trust.default-https-port=443
 *
 * # ── Socket timeout for bootstrap cert-fetch handshake ──────────────────
 * ssl.auto-trust.connect-timeout-ms=10000
 *
 * # ── Suppress auto-configured RestTemplate @Bean ─────────────────────────
 * # Set false if you define your own RestTemplate bean.
 * ssl.auto-trust.rest-template-enabled=true
 * </pre>
 */
@ConfigurationProperties(prefix = "ssl.auto-trust")
public class SslAutoTrustProperties {

    /**
     * Master switch.
     * <p><b>Default: {@code false}</b> — the starter does nothing until this
     * is explicitly set to {@code true} or {@code @EnableSslAutoTrust} is used.
     * This prevents accidental cert-fetching on machines that do not need it.
     */
    private boolean enabled = false;

    /**
     * Comma-separated domain/URL list to auto-trust.
     * Default covers two public GitHub hosts useful for testing.
     */
    private List<String> domains = Arrays.asList(
            "github.com",
            "api.github.com"
    );

    /** Directory where .cer files and combined-truststore.jks are written. */
    private String exportDir = "exportedcerts";

    /**
     * Password for the persisted combined-truststore.jks (offline inspection).
     * Not used at runtime — JVM truststore is always patched in-memory.
     */
    private String truststorePassword = "changeit";

    /** Port assumed when domain entry has no explicit port. */
    private int defaultHttpsPort = 443;

    /** Socket timeout in milliseconds for the bootstrap TLS handshake. */
    private int connectTimeoutMs = 10_000;

    /**
     * When {@code true}, registers a {@link org.springframework.web.client.RestTemplate}
     * {@code @Bean} with an explicit SSL context. Set to {@code false} when
     * the consuming app defines its own {@code RestTemplate} bean.
     */
    private boolean restTemplateEnabled = true;

    // ── Getters & Setters ────────────────────────────────────────────────────

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public List<String> getDomains() { return domains; }
    public void setDomains(List<String> domains) { this.domains = domains; }

    public String getExportDir() { return exportDir; }
    public void setExportDir(String exportDir) { this.exportDir = exportDir; }

    public String getTruststorePassword() { return truststorePassword; }
    public void setTruststorePassword(String truststorePassword) { this.truststorePassword = truststorePassword; }

    public int getDefaultHttpsPort() { return defaultHttpsPort; }
    public void setDefaultHttpsPort(int defaultHttpsPort) { this.defaultHttpsPort = defaultHttpsPort; }

    public int getConnectTimeoutMs() { return connectTimeoutMs; }
    public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }

    public boolean isRestTemplateEnabled() { return restTemplateEnabled; }
    public void setRestTemplateEnabled(boolean restTemplateEnabled) { this.restTemplateEnabled = restTemplateEnabled; }
}
