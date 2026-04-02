package com.github.yash777.sslautotrust.core;

import com.github.yash777.sslautotrust.autoconfigure.SslAutoTrustProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * SslTrustCore
 *
 * <p>Stateless shared utility layer. Both
 * {@link com.github.yash777.sslautotrust.initializer.SslAutoTrustInitializer} and
 * {@link com.github.yash777.sslautotrust.autoconfigure.SslAutoTrustAutoConfiguration}
 * delegate all heavy lifting here.
 *
 * <h3>Responsibilities</h3>
 * <ul>
 *   <li>Domain/URL parsing → bare hostname + port</li>
 *   <li>Loading the JVM {@code cacerts} truststore from disk</li>
 *   <li>Fetching live TLS cert chain via a scoped trust-all handshake</li>
 *   <li>NEW / SKIP / UPDATE sync of on-disk {@code .cer} files and in-memory KeyStore</li>
 *   <li>Writing PEM-encoded {@code .cer} files</li>
 *   <li>Persisting the combined truststore as a {@code .jks} file</li>
 *   <li>Installing the patched {@link SSLContext} as the JVM-wide default</li>
 * </ul>
 *
 * <h3>Thread safety</h3>
 * All methods are stateless. The only state is the read-only
 * {@link SslAutoTrustProperties} reference passed at construction.
 */
public class SslTrustCore {

    private static final Logger log = LoggerFactory.getLogger(SslTrustCore.class);
    private static final String CACERTS_PASSWORD = "changeit";

    private final SslAutoTrustProperties props;

    public SslTrustCore(SslAutoTrustProperties props) {
        this.props = props;
    }

    // ── Domain parsing ────────────────────────────────────────────────────────

    /**
     * Extracts a bare hostname from any domain entry format:
     * {@code https://host.example.com/path} → {@code host.example.com}
     * {@code host.example.com}              → {@code host.example.com}
     * {@code internal.local:8443}           → {@code internal.local}
     */
    public String resolveHost(String entry) {
        String s = entry.trim();
        if (s.startsWith("https://")) s = s.substring(8);
        if (s.startsWith("http://"))  s = s.substring(7);
        int slash = s.indexOf('/');
        if (slash != -1) s = s.substring(0, slash);
        int colon = s.indexOf(':');
        if (colon != -1) s = s.substring(0, colon);
        return s.trim();
    }

    /**
     * Extracts TCP port from any domain entry format.
     * Falls back to {@link SslAutoTrustProperties#getDefaultHttpsPort()} (443).
     */
    public int resolvePort(String entry) {
        String s = entry.trim();
        if (s.startsWith("https://")) s = s.substring(8);
        if (s.startsWith("http://"))  s = s.substring(7);
        int slash = s.indexOf('/');
        if (slash != -1) s = s.substring(0, slash);
        int colon = s.indexOf(':');
        if (colon != -1) {
            try { return Integer.parseInt(s.substring(colon + 1).trim()); }
            catch (NumberFormatException e) {
                log.warn("[ssl-auto-trust] Bad port in '{}' — using {}", entry, props.getDefaultHttpsPort());
            }
        }
        return props.getDefaultHttpsPort();
    }

    // ── JVM truststore ────────────────────────────────────────────────────────

    /**
     * Loads JVM cacerts ({@code $JAVA_HOME/lib/security/cacerts} for Java 11+,
     * {@code $JAVA_HOME/jre/lib/security/cacerts} for Java 8) as the base KeyStore.
     * Using cacerts as base ensures {@code trustAnchors} is never empty.
     */
    public KeyStore loadJvmCacerts() throws Exception {
        String javaHome = System.getProperty("java.home");
        File cacerts = new File(javaHome, "lib/security/cacerts");
        if (!cacerts.exists()) cacerts = new File(javaHome, "jre/lib/security/cacerts");
        if (!cacerts.exists()) throw new FileNotFoundException(
                "[ssl-auto-trust] Cannot locate cacerts. Checked: " + cacerts.getAbsolutePath());
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(cacerts)) {
            ks.load(fis, CACERTS_PASSWORD.toCharArray());
        }
        log.info("[ssl-auto-trust] Loaded JVM cacerts ({} entries) from {}", ks.size(), cacerts.getAbsolutePath());
        return ks;
    }

    /**
     * Installs a patched KeyStore as the JVM-wide default SSLContext.
     * Patches two surfaces:
     * (1) {@link SSLContext#setDefault} — covers all modern SSL clients.
     * (2) {@link HttpsURLConnection#setDefaultSSLSocketFactory} — legacy java.net.
     */
    public void installAsJvmDefault(KeyStore trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
        SSLContext.setDefault(ctx);
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        log.info("[ssl-auto-trust] JVM-wide SSLContext installed ({} trust entries)", trustStore.size());
    }

    // ── Certificate fetching ──────────────────────────────────────────────────

    /**
     * Opens a temporary trust-all TLS socket to capture the server cert chain.
     * The trust-all TrustManager is intentional and scoped to this bootstrap
     * socket only — it is discarded immediately after the chain is captured.
     */
    public List<X509Certificate> fetchCertChain(String host, int port) {
        List<X509Certificate> chain = new ArrayList<X509Certificate>();
        try {
            final X509Certificate[][] holder = new X509Certificate[1][];
            SSLContext trustAll = SSLContext.getInstance("TLS");
            trustAll.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) { holder[0] = c; }
                public X509Certificate[] getAcceptedIssuers() {
                    return holder[0] != null ? holder[0] : new X509Certificate[0];
                }
            }}, new SecureRandom());
            SSLSocket sock = (SSLSocket) trustAll.getSocketFactory().createSocket(host, port);
            try {
                sock.setSoTimeout(props.getConnectTimeoutMs());
                sock.startHandshake();
                for (Certificate c : sock.getSession().getPeerCertificates()) {
                    if (c instanceof X509Certificate) chain.add((X509Certificate) c);
                }
            } finally {
                try { sock.close(); } catch (Exception ignored) {}
            }
            log.info("[ssl-auto-trust] Fetched {} cert(s) from {}:{}", chain.size(), host, port);
        } catch (Exception e) {
            log.error("[ssl-auto-trust] Fetch failed {}:{} — {}", host, port, e.getMessage());
        }
        return chain;
    }

    // ── High-level domain processor ───────────────────────────────────────────

    /**
     * Resolves host+port, fetches chain, and syncs to disk + KeyStore.
     * Returns {@code true} if the KeyStore was modified.
     */
    public boolean processDomain(String entry, KeyStore keyStore) {
        String host = resolveHost(entry);
        int    port = resolvePort(entry);
        log.info("[ssl-auto-trust] Processing {}:{}", host, port);
        List<X509Certificate> chain = fetchCertChain(host, port);
        if (chain.isEmpty()) {
            log.warn("[ssl-auto-trust] No certs from {} — skipping", host);
            return false;
        }
        return syncCertsAndKeyStore(keyStore, host, chain);
    }

    // ── Cert sync ─────────────────────────────────────────────────────────────

    /**
     * [NEW]    no .cer file → write + import.
     * [SKIP]   file exists, same byte-size → unchanged.
     * [UPDATE] file exists, different size → overwrite + replace alias.
     */
    public boolean syncCertsAndKeyStore(KeyStore keyStore, String host, List<X509Certificate> chain) {
        boolean modified = false;
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert  = chain.get(i);
            String fileName = host + "-cert-" + i + ".cer";
            Path   filePath = Paths.get(props.getExportDir(), fileName);
            String alias    = host.replace(".", "-") + "-" + i;
            try {
                byte[] liveBytes = cert.getEncoded();
                if (!Files.exists(filePath)) {
                    log.info("[ssl-auto-trust] [NEW]    {}", fileName);
                    writeCertFile(filePath, liveBytes);
                    addToKeyStore(keyStore, alias, cert);
                    modified = true;
                } else {
                    long diskSize = Files.size(filePath);
                    if (diskSize == liveBytes.length) {
                        log.info("[ssl-auto-trust] [SKIP]   {} ({}B — unchanged)", fileName, diskSize);
                    } else {
                        log.info("[ssl-auto-trust] [UPDATE] {} disk={}B live={}B", fileName, diskSize, liveBytes.length);
                        writeCertFile(filePath, liveBytes);
                        removeFromKeyStore(keyStore, alias);
                        addToKeyStore(keyStore, alias, cert);
                        modified = true;
                    }
                }
            } catch (Exception e) {
                log.error("[ssl-auto-trust] Error cert[{}] {} — {}", i, host, e.getMessage());
            }
        }
        return modified;
    }

    public void addToKeyStore(KeyStore ks, String alias, X509Certificate cert) throws KeyStoreException {
        if (!ks.containsAlias(alias)) {
            ks.setCertificateEntry(alias, cert);
            log.info("[ssl-auto-trust]   keystore ← '{}'", alias);
        }
    }

    public void removeFromKeyStore(KeyStore ks, String alias) throws KeyStoreException {
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias);
            log.info("[ssl-auto-trust]   keystore removed '{}'", alias);
        }
    }

    public void writeCertFile(Path path, byte[] encoded) throws IOException {
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded)
                + "\n-----END CERTIFICATE-----\n";
        Files.write(path, pem.getBytes(StandardCharsets.UTF_8));
    }

    /** Persists combined-truststore.jks to {@code <export-dir>/}. For offline inspection only. */
    public void persistKeyStore(KeyStore ks) {
        Path jksPath = Paths.get(props.getExportDir(), "combined-truststore.jks");
        try (FileOutputStream fos = new FileOutputStream(jksPath.toFile())) {
            ks.store(fos, props.getTruststorePassword().toCharArray());
            log.info("[ssl-auto-trust] JKS saved → {}", jksPath.toAbsolutePath());
        } catch (Exception e) {
            log.error("[ssl-auto-trust] JKS save failed — {}", e.getMessage());
        }
    }
}
