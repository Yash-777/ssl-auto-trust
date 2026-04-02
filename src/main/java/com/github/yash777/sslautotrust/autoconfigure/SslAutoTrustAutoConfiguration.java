package com.github.yash777.sslautotrust.autoconfigure;

import com.github.yash777.sslautotrust.core.SslTrustCore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * SslAutoTrustAutoConfiguration
 *
 * <p>Auto-configuration class for the SSL Auto-Trust starter.
 * Registered via {@code META-INF/spring.factories} (Spring Boot 2.x) and
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * (Spring Boot 3.x).
 *
 * <h3>Activation — DISABLED by default</h3>
 * This class is guarded by {@code @ConditionalOnProperty} requiring
 * {@code ssl.auto-trust.enabled=true}. The default is {@code false}, so this
 * class is a no-op unless explicitly enabled via:
 * <ul>
 *   <li>{@code ssl.auto-trust.enabled=true} in {@code application.properties}</li>
 *   <li>{@link com.github.yash777.sslautotrust.annotation.EnableSslAutoTrust @EnableSslAutoTrust}
 *       annotation (uses {@code @Import} — bypasses the conditional guard,
 *       but the property still overrides if set to {@code false})</li>
 * </ul>
 *
 * <h3>Relationship with SslAutoTrustInitializer</h3>
 * <ul>
 *   <li>{@link com.github.yash777.sslautotrust.initializer.SslAutoTrustInitializer} —
 *       fires at {@code ApplicationEnvironmentPreparedEvent} (before any bean).
 *       Patches the JVM-wide default {@link javax.net.ssl.SSLContext}.</li>
 *   <li>This class — fires during normal context refresh.
 *       Produces a per-client {@link RestTemplate} with its own explicit
 *       {@link SSLContext}. Acts as a second layer of defence.</li>
 * </ul>
 */
@Configuration
@ConditionalOnProperty(
        prefix = "ssl.auto-trust",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = false   // DEFAULT FALSE — disabled unless explicitly enabled
)
@EnableConfigurationProperties(SslAutoTrustProperties.class)
public class SslAutoTrustAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SslAutoTrustAutoConfiguration.class);

    /**
     * Produces a {@link RestTemplate} with an explicit SSL truststore containing
     * the certs from every configured domain.
     *
     * <p>Guards:
     * <ul>
     *   <li>{@code ssl.auto-trust.rest-template-enabled=true} (default)</li>
     *   <li>{@code @ConditionalOnMissingBean} — yields to consumer's own RestTemplate</li>
     *   <li>{@code @ConditionalOnWebApplication} — not registered in CLI/batch contexts</li>
     * </ul>
     */
    @Bean
    @ConditionalOnMissingBean(RestTemplate.class)
    @ConditionalOnWebApplication
    @ConditionalOnProperty(
            prefix = "ssl.auto-trust",
            name = "rest-template-enabled",
            havingValue = "true",
            matchIfMissing = true
    )
    public RestTemplate sslAutoTrustRestTemplate(SslAutoTrustProperties props) throws Exception {
        log.info("[ssl-auto-trust] Building SSL-aware RestTemplate");

        SslTrustCore core = new SslTrustCore(props);
        Files.createDirectories(Paths.get(props.getExportDir()));

        KeyStore trustStore = core.loadJvmCacerts();
        for (String entry : props.getDomains()) {
            try {
                core.processDomain(entry, trustStore);
            } catch (Exception e) {
                log.error("[ssl-auto-trust] @Bean: domain '{}' failed — {}", entry, e.getMessage());
            }
        }
        core.persistKeyStore(trustStore);

        SSLContext sslContext = SSLContextBuilder.create()
                .loadTrustMaterial(trustStore, null)
                .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();

        log.info("[ssl-auto-trust] RestTemplate ready ({} trust entries). Certs → {}/",
                trustStore.size(), Paths.get(props.getExportDir()).toAbsolutePath());

        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));
    }
}
