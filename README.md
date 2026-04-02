# ssl-auto-trust-spring-boot-starter

[![Maven Central](https://img.shields.io/maven-central/v/io.github.yash-777/ssl-auto-trust-spring-boot-starter)](https://central.sonatype.com/artifact/io.github.yash-777/ssl-auto-trust-spring-boot-starter)
[![Java 8+](https://img.shields.io/badge/Java-8%2B-blue)](https://www.java.com)
[![Spring Boot 2.x](https://img.shields.io/badge/Spring%20Boot-2.x-green)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)

> **Version: 1.0.0**

Zero-config Spring Boot 2.x starter that automatically trusts ZScaler and corporate-proxy TLS certificates at the **earliest possible lifecycle hook** — before any `@Bean`, `@PostConstruct`, or Feign client runs.

**Fixes:**
```
org.springframework.web.client.ResourceAccessException: I/O error on POST request
for "https://...": PKIX path building failed: unable to find valid certification path
```

---

## What is this solving?

Corporate firewalls (ZScaler, Cisco Umbrella, Netskope, Palo Alto Prisma, etc.) act as SSL inspection proxies. They replace the original server TLS certificate with one signed by the corporate Root CA. The JVM does not recognise this corporate CA, so every HTTPS call fails with `PKIX path building failed`.

This starter:
1. Fetches the live TLS certificate chain from each configured domain on startup
2. Imports the chain into the JVM's in-memory truststore
3. Installs the patched truststore as the **JVM-wide default SSLContext** — all HTTPS calls in the entire JVM are fixed automatically

---

## Default: DISABLED

The starter is **off by default** — it does nothing unless explicitly enabled. This prevents accidental cert-fetching on developer machines or production environments that don't need it.

Enable via property:
```properties
ssl.auto-trust.enabled=true
```

Or via annotation:
```java
@SpringBootApplication
@EnableSslAutoTrust
public class MyApplication { ... }
```

---

## Requirements

| Requirement       | Version                    |
|-------------------|----------------------------|
| Java              | 8 or higher                |
| Spring Boot       | 2.x (tested 2.0.x – 2.7.x)|
| Apache HttpClient | 4.x (via Spring Boot BOM)  |
| OS                | Windows / Linux / macOS    |

---

## Installation

### Maven (after publishing to Central)
```xml
<dependency>
  <groupId>io.github.yash-777</groupId>
  <artifactId>ssl-auto-trust-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Local install (before Central publishing)
```bash
cd ssl-auto-trust-spring-boot-starter
mvn clean install -DskipTests
```
Then add the dependency above to your consuming project's `pom.xml`.

---

## Quick Start

### Option A — Property activation (recommended)

No code change in `main()` needed. Just set the property:

```properties
# application.properties
ssl.auto-trust.enabled=true
ssl.auto-trust.domains=\
  https://azuredownloads-g3ahgwb5b8bkbxhd.b01.azurefd.net/github-copilot/content.xml,\
  https://api.github.com/,\
  https://marketplace.eclipse.org/content/github-copilot,\
  https://docs.github.com/en/copilot/how-tos/get-code-suggestions/get-ide-code-suggestions
```

The starter auto-registers itself via `META-INF/spring.factories`. Both the early listener and the RestTemplate bean become active.

### Option B — Annotation activation

```java
@SpringBootApplication
@EnableSslAutoTrust
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

Then add your domains to `application.properties`:
```properties
ssl.auto-trust.domains=your-corporate-host.com,internal-api.local:8443
```

### Option C — Manual listener registration (original approach, still works)

```java
public static void main(String[] args) {
    SpringApplication app = new SpringApplication(MyApplication.class);
    app.addListeners(new SslAutoTrustInitializer());
    app.run(args);
}
```

---

## How It Works

```
JVM starts
    │
    ├─ spring.factories auto-registers SslAutoTrustInitializer
    │
    ▼
ApplicationEnvironmentPreparedEvent  ← earliest Spring Boot hook
    │   (before ANY @Bean, @PostConstruct, Feign, RestTemplate)
    │
    ├─ Checks ssl.auto-trust.enabled (default: false → no-op)
    ├─ If enabled=true:
    │     ├─ Reads ssl.auto-trust.* from raw Environment
    │     ├─ Loads $JAVA_HOME/lib/security/cacerts as base
    │     ├─ For each domain in ssl.auto-trust.domains:
    │     │     ├─ Trust-all TLS socket → captures live cert chain
    │     │     ├─ [NEW]    writes .cer file + adds alias to KeyStore
    │     │     ├─ [SKIP]   cert unchanged (byte-size match) → no-op
    │     │     └─ [UPDATE] cert rotated → overwrites file + alias
    │     ├─ SSLContext.setDefault(patched)     ← JVM-wide
    │     └─ HttpsURLConnection.setDefaultSSLSocketFactory(patched)
    │
    ▼
Spring context refresh (@Bean lifecycle)
    │
    ├─ SslAutoTrustAutoConfiguration (if enabled=true)
    │     └─ RestTemplate @Bean with explicit per-client SSLContext
    │         (second layer — works even if listener was skipped)
    │
    ▼
Application running
    └─ All HTTPS (RestTemplate, Feign, OkHttp, java.net) trust ZScaler
```

---

## Configuration Reference

All properties are under `ssl.auto-trust.*`.

| Property | Default | Description |
|----------|---------|-------------|
| `ssl.auto-trust.enabled` | **`false`** | **Master switch — must be set to `true` to activate** |
| `ssl.auto-trust.domains` | `github.com,api.github.com` | Comma-separated domain list |
| `ssl.auto-trust.export-dir` | `exportedcerts` | Directory for `.cer` files and combined JKS |
| `ssl.auto-trust.truststore-password` | `changeit` | JKS password (offline inspection only) |
| `ssl.auto-trust.default-https-port` | `443` | Port assumed when not specified in domain |
| `ssl.auto-trust.connect-timeout-ms` | `10000` | Cert-fetch handshake timeout (ms) |
| `ssl.auto-trust.rest-template-enabled` | `true` | When `false`, suppresses the auto-configured RestTemplate |

### Full `application.properties` example

```properties
# ── ssl-auto-trust-spring-boot-starter ──────────────────────────────────────

# REQUIRED: master switch (default false — nothing runs without this)
ssl.auto-trust.enabled=true

# Corporate / Einvironment endpoints behind ZScaler
ssl.auto-trust.domains=\
  https://azuredownloads-g3ahgwb5b8bkbxhd.b01.azurefd.net/github-copilot/content.xml,\
  https://api.github.com/,\
  https://marketplace.eclipse.org/content/github-copilot,\
  https://docs.github.com/en/copilot/how-tos/get-code-suggestions/get-ide-code-suggestions,\
  internal-service.local:8443

# Optional overrides (all have sensible defaults)
ssl.auto-trust.export-dir=exportedcerts
ssl.auto-trust.truststore-password=changeit
ssl.auto-trust.default-https-port=443
ssl.auto-trust.connect-timeout-ms=10000

# Set false if you define your own RestTemplate bean
ssl.auto-trust.rest-template-enabled=true
```

---

## Accepted Domain Formats

```properties
# Full HTTPS URL — scheme and path stripped automatically
ssl.auto-trust.domains=https://app.env.example.com/platform/oauth/oauth2/token

# Bare hostname — port defaults to 443
ssl.auto-trust.domains=app.env.example.com

# Host:port — for non-443 internal services
ssl.auto-trust.domains=internal-api.local:8443

# Mix all three
ssl.auto-trust.domains=\
  https://app.env.example.com/path,\
  bare.example.com,\
  internal.local:8443
```

---

## Disabling Per Environment

```properties
# application-prod.properties — production uses standard JVM certs
ssl.auto-trust.enabled=false
```

```properties
# application-dev.properties — local dev through ZScaler
ssl.auto-trust.enabled=true
ssl.auto-trust.domains=your-dev-backend.company.com
```

---

## Using Your Own RestTemplate

If your app defines its own `RestTemplate` bean, suppress the starter's bean:
```properties
ssl.auto-trust.rest-template-enabled=false
```

The JVM-wide SSLContext patch still applies — your RestTemplate benefits automatically.

To use `SslTrustCore` directly in your own bean:
```java
@Configuration
public class MyHttpConfig {

    @Autowired
    private SslAutoTrustProperties props;

    @Bean
    public RestTemplate myRestTemplate() throws Exception {
        SslTrustCore core = new SslTrustCore(props);
        KeyStore ts = core.loadJvmCacerts();
        for (String domain : props.getDomains()) {
            core.processDomain(domain, ts);
        }
        SSLContext ctx = SSLContextBuilder.create().loadTrustMaterial(ts, null).build();
        CloseableHttpClient client = HttpClients.custom().setSSLContext(ctx).build();
        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(client));
    }
}
```

---

## Exported Files

On first startup, `exportedcerts/` (or your configured `export-dir`) contains:

```
exportedcerts/
├── github.com-cert-0.cer          ← leaf cert (PEM)
├── github.com-cert-1.cer          ← intermediate CA
├── github.com-cert-2.cer          ← root CA
├── api.github.com-cert-0.cer
├── ...
└── combined-truststore.jks        ← all certs combined (for keytool inspection)
```

Inspect with keytool:
```bash
keytool -list -keystore exportedcerts/combined-truststore.jks -storepass changeit
```

---

## Project Structure

```
ssl-auto-trust-spring-boot-starter/
├── pom.xml
└── src/main/
    ├── java/com/github/yash777/sslautotrust/
    │   ├── annotation/
    │   │   └── EnableSslAutoTrust.java          ← @EnableSslAutoTrust annotation
    │   ├── autoconfigure/
    │   │   ├── SslAutoTrustProperties.java      ← @ConfigurationProperties (ssl.auto-trust.*)
    │   │   └── SslAutoTrustAutoConfiguration.java ← @Configuration + RestTemplate @Bean
    │   ├── core/
    │   │   └── SslTrustCore.java                ← shared stateless utilities
    │   ├── initializer/
    │   │   └── SslAutoTrustInitializer.java     ← ApplicationEnvironmentPreparedEvent listener
    │   ├── util/
    │   │   ├── SslCertificateUtils.java         ← cert inspection + PEM + expiry checks
    │   │   └── HttpConnectionUtils.java         ← GET, proxy detect, DNS, reachability
    │   └── demo/
    │       ├── SslFetchTest.java                ← standalone PKIX fix demo
    │       └── NetworkDiagnosticsDemo.java      ← full network + cert diagnostics
    └── resources/META-INF/
        ├── spring.factories                     ← Spring Boot 2.x SPI registration
        ├── spring/
        │   └── org.springframework.boot.autoconfigure.AutoConfiguration.imports  ← Boot 3.x
        └── additional-spring-configuration-metadata.json  ← IDE autocomplete hints
```

---

## Comparison

| | This starter | Manual keytool | `-Djavax.net.ssl.trustStore` |
|---|---|---|---|
| Zero config | ✅ | ❌ | ❌ |
| Auto-detects cert rotation | ✅ | ❌ | ❌ |
| Fires before any @Bean | ✅ | n/a | n/a |
| Disabled by default (safe) | ✅ | n/a | n/a |
| Java 8 compatible | ✅ | ✅ | ✅ |
| Works on Windows | ✅ | ✅ | ✅ |
| No keytool required | ✅ | ❌ | ❌ |
| Covers Feign, OkHttp, java.net | ✅ | ❌ | ✅ |
