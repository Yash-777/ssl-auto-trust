package com.github.yash777.sslautotrust.demo;

import com.github.yash777.sslautotrust.util.HttpConnectionUtils;
import com.github.yash777.sslautotrust.util.SslCertificateUtils;

import javax.net.ssl.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * SslFetchTest
 *
 * <p>Standalone demo — Java 8, no Spring, no Maven dependencies.
 * Demonstrates the full PKIX auto-trust flow for the URLs that triggered
 * the original Eclipse GitHub Copilot plugin installation failure.
 *
 * <p>Run from IDE: right-click → Run As → Java Application.
 * Run from CLI: {@code javac SslFetchTest.java && java SslFetchTest}
 */
public class SslFetchTest {

    private static final List<String> TARGET_URL_LIST = Arrays.asList(
        // Eclipse GitHub Copilot plugin update site — original problem URL
        "https://azuredownloads-g3ahgwb5b8bkbxhd.b01.azurefd.net/github-copilot/content.xml",
        // GitHub REST API — public test host, fast, clean chain
        "https://api.github.com/",
        // Eclipse Marketplace listing
        "https://marketplace.eclipse.org/content/github-copilot",
        // GitHub Copilot docs
        "https://docs.github.com/en/copilot/how-tos/get-code-suggestions/get-ide-code-suggestions"
    );

    private static final int TIMEOUT_MS = 15_000;

    public static void main(String[] args) throws Exception {
        System.setProperty("http.keepAlive", "false");

        printBanner();

        // PHASE 0 — Network diagnostics
        System.out.println("\n[PHASE 0] Diagnostics");
        HttpConnectionUtils.printProxySettings();
        HttpConnectionUtils.printDnsInfo("api.github.com");
        System.out.println("  Proxy intercepting api.github.com: "
                + HttpConnectionUtils.isProxyIntercepting("api.github.com", 443));

        // PHASE 1 — Raw fetch: identify PKIX failures
        System.out.println("\n[PHASE 1] Raw fetch — identifying PKIX issues");
        List<String> pkixTargets = new ArrayList<String>();
        for (String url : TARGET_URL_LIST) {
            try {
                HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
                conn.setConnectTimeout(TIMEOUT_MS); conn.setReadTimeout(TIMEOUT_MS);
                int status = conn.getResponseCode();
                System.out.println("  [OK " + status + "] " + url);
                conn.disconnect();
            } catch (SSLHandshakeException e) {
                System.out.println("  [PKIX] " + url);
                pkixTargets.add(url);
            } catch (Exception e) {
                System.out.println("  [ERR] " + url + " — " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        if (pkixTargets.isEmpty()) {
            System.out.println("\n[INFO] No PKIX errors. ZScaler cert already trusted by this JVM.");
            SslCertificateUtils.printCertChain("api.github.com", 443);
            return;
        }

        // PHASE 2 — Capture cert chains + print details
        System.out.println("\n[PHASE 2] Capturing cert chains");
        KeyStore trustStore = SslCertificateUtils.loadJvmCacerts();
        System.out.println("  Base cacerts loaded (" + trustStore.size() + " entries)");

        for (String url : pkixTargets) {
            String host = extractHost(url);
            SslCertificateUtils.printCertChain(host, 443);
            List<X509Certificate> chain = SslCertificateUtils.fetchChain(host, 443);
            if (chain.isEmpty()) continue;

            // PHASE 3 — Import into in-memory KeyStore
            System.out.println("[PHASE 3] Importing " + chain.size() + " cert(s) from " + host);
            for (int i = 0; i < chain.size(); i++) {
                String alias = "autotrust-" + host.replace(".", "-") + "-" + i;
                if (!trustStore.containsAlias(alias)) {
                    trustStore.setCertificateEntry(alias, chain.get(i));
                    System.out.println("  Imported: " + alias);
                } else {
                    System.out.println("  Exists  : " + alias);
                }
            }
            SslCertificateUtils.printExpiryWarnings(chain, 30);
        }

        // PHASE 4 — Patch JVM-wide SSLContext
        System.out.println("\n[PHASE 4] Patching JVM-wide SSLContext");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
        SSLContext.setDefault(ctx);
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        System.out.println("  Done. Trust entries: " + trustStore.size());

        // PHASE 5 — Re-fetch with patched truststore
        System.out.println("\n[PHASE 5] Re-fetching with patched truststore");
        for (String url : pkixTargets) {
            HttpConnectionUtils.get(url, TIMEOUT_MS);
        }

        System.out.println("\n" + repeat("═", 60));
        System.out.println("  Tip: add failing hosts to ssl.auto-trust.domains");
        System.out.println("       and set ssl.auto-trust.enabled=true");
        System.out.println(repeat("═", 60));
    }

    private static String extractHost(String url) {
        String s = url;
        if (s.startsWith("https://")) s = s.substring(8);
        if (s.startsWith("http://"))  s = s.substring(7);
        int slash = s.indexOf('/'); if (slash != -1) s = s.substring(0, slash);
        int colon = s.indexOf(':');  if (colon != -1) s = s.substring(0, colon);
        return s.trim();
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }

    private static void printBanner() {
        System.out.println(repeat("═", 60));
        System.out.println("  SslFetchTest — PKIX Auto-Trust Demo");
        System.out.println("  Java : " + System.getProperty("java.version"));
        System.out.println("  OS   : " + System.getProperty("os.name"));
        System.out.println("  Home : " + System.getProperty("java.home"));
        System.out.println(repeat("─", 60));
        for (String u : TARGET_URL_LIST) System.out.println("  • " + u);
        System.out.println(repeat("═", 60));
    }
}
