package com.github.yash777.sslautotrust.initializer;

import com.github.yash777.sslautotrust.autoconfigure.SslAutoTrustProperties;
import com.github.yash777.sslautotrust.core.SslTrustCore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.Environment;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

/**
 * SslAutoTrustInitializer
 *
 * <p>Spring Boot {@link ApplicationListener} that patches the JVM default SSL
 * truststore at {@link ApplicationEnvironmentPreparedEvent} — the earliest
 * possible lifecycle hook, before any {@code @Bean}, {@code @PostConstruct},
 * or Feign client is initialised.
 *
 * <h3>Auto-registration (zero consumer code needed)</h3>
 * Registered in {@code META-INF/spring.factories} as an ApplicationListener:
 * <pre>
 * org.springframework.context.ApplicationListener=\
 *   com.github.yash777.sslautotrust.initializer.SslAutoTrustInitializer
 * </pre>
 * No {@code app.addListeners()} call needed in {@code main()} when the
 * starter JAR is on the classpath. The {@code addListeners()} approach still
 * works as a manual override if preferred.
 *
 * <h3>Kill-switch (DEFAULT: disabled)</h3>
 * The listener checks {@code ssl.auto-trust.enabled} (default {@code false})
 * at runtime. It exits immediately unless the property is {@code true}.
 * This is the earliest property read — directly from the raw {@link Environment}.
 *
 * <h3>Failure policy</h3>
 * All exceptions are caught and logged. Startup is never aborted.
 * If the listener fails, {@link com.github.yash777.sslautotrust.autoconfigure.SslAutoTrustAutoConfiguration}
 * retries during context refresh.
 */
public class SslAutoTrustInitializer
        implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    private static final Logger log = LoggerFactory.getLogger(SslAutoTrustInitializer.class);

    // Mirrors SslAutoTrustProperties defaults — DI not available at this stage
    private static final String DEFAULT_DOMAINS    = "github.com,api.github.com";
    private static final String DEFAULT_EXPORT_DIR = "exportedcerts";
    private static final String DEFAULT_TS_PASS    = "changeit";
    private static final int    DEFAULT_PORT       = 443;
    private static final int    DEFAULT_TIMEOUT_MS = 10_000;

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        Environment env = event.getEnvironment();

        // ── Kill-switch check — DEFAULT FALSE ────────────────────────────────
        // @ConfigurationProperties binding is NOT available at this stage.
        // Read directly from the raw Environment.
        boolean enabled = Boolean.parseBoolean(env.getProperty("ssl.auto-trust.enabled", "false"));
        if (!enabled) {
            log.debug("[ssl-auto-trust] Disabled (ssl.auto-trust.enabled=false) — skipping early patch");
            return;
        }

        log.info("[ssl-auto-trust] SslAutoTrustInitializer — patching JVM truststore before context load");

        String exportDir  = env.getProperty("ssl.auto-trust.export-dir",          DEFAULT_EXPORT_DIR);
        String tsPassword = env.getProperty("ssl.auto-trust.truststore-password",  DEFAULT_TS_PASS);
        String domainsRaw = env.getProperty("ssl.auto-trust.domains",              DEFAULT_DOMAINS);
        int    defPort    = parseInt(env.getProperty("ssl.auto-trust.default-https-port"), DEFAULT_PORT);
        int    timeoutMs  = parseInt(env.getProperty("ssl.auto-trust.connect-timeout-ms"), DEFAULT_TIMEOUT_MS);

        List<String> domains = parseDomains(domainsRaw);
        log.info("[ssl-auto-trust] Domains: {}", domains);

        SslAutoTrustProperties props = new SslAutoTrustProperties();
        props.setEnabled(true);
        props.setDomains(domains);
        props.setExportDir(exportDir);
        props.setTruststorePassword(tsPassword);
        props.setDefaultHttpsPort(defPort);
        props.setConnectTimeoutMs(timeoutMs);

        SslTrustCore core = new SslTrustCore(props);

        try {
            Files.createDirectories(Paths.get(exportDir));
            KeyStore jvmTrustStore = core.loadJvmCacerts();
            boolean  modified      = false;

            for (String entry : domains) {
                try {
                    if (core.processDomain(entry, jvmTrustStore)) modified = true;
                } catch (Exception e) {
                    log.error("[ssl-auto-trust] Domain '{}' failed — {}", entry, e.getMessage());
                }
            }

            if (modified) {
                core.installAsJvmDefault(jvmTrustStore);
                core.persistKeyStore(jvmTrustStore);
                log.info("[ssl-auto-trust] JVM truststore patched and installed successfully");
            } else {
                log.info("[ssl-auto-trust] All certs up-to-date — no JVM truststore changes needed");
            }
        } catch (Exception e) {
            log.error("[ssl-auto-trust] Early patch failed — {}. Falling back to default JVM SSL.", e.getMessage(), e);
        }
    }

    private static List<String> parseDomains(String raw) {
        List<String> result = new ArrayList<String>();
        if (raw == null || raw.trim().isEmpty()) return result;
        for (String part : raw.split(",")) {
            String t = part.trim();
            if (!t.isEmpty()) result.add(t);
        }
        return result;
    }

    private static int parseInt(String value, int def) {
        if (value == null) return def;
        try { return Integer.parseInt(value.trim()); }
        catch (NumberFormatException e) { return def; }
    }
}
