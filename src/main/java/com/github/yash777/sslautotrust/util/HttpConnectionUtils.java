package com.github.yash777.sslautotrust.util;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * HttpConnectionUtils
 *
 * <p>Standalone HTTP/HTTPS network utilities. Zero Spring dependencies.
 *
 * <pre>{@code
 * // Quick GET with status, headers, body
 * HttpConnectionUtils.get("https://api.github.com/", 10_000);
 *
 * // Detect corporate proxy / ZScaler interception
 * boolean behind = HttpConnectionUtils.isProxyIntercepting("github.com", 443);
 *
 * // Print all response headers
 * HttpConnectionUtils.printHeaders("https://api.github.com/");
 *
 * // TCP reachability (no TLS handshake)
 * boolean up = HttpConnectionUtils.isReachable("github.com", 443, 5_000);
 *
 * // DNS resolution details
 * HttpConnectionUtils.printDnsInfo("github.com");
 *
 * // Print current JVM proxy settings
 * HttpConnectionUtils.printProxySettings();
 * }</pre>
 */
public final class HttpConnectionUtils {

    private HttpConnectionUtils() {}

    /**
     * Performs a GET request and prints HTTP status, selected headers,
     * and up to 1000 characters of the response body.
     */
    public static void get(String urlStr, int timeoutMs) {
        System.out.println("\nGET " + urlStr);
        System.out.println(line(60));
        try {
            HttpURLConnection conn = open(urlStr, timeoutMs);
            int status = conn.getResponseCode();
            System.out.println("Status  : " + status + " " + conn.getResponseMessage());
            System.out.println("Type    : " + conn.getContentType());
            InputStream is = (status >= 200 && status < 300)
                    ? conn.getInputStream() : conn.getErrorStream();
            if (is != null) {
                System.out.println("Body    :\n" + readAtMost(is, 1000));
            }
            conn.disconnect();
        } catch (SSLHandshakeException e) {
            System.out.println("[PKIX] " + e.getMessage());
            System.out.println("→ Enable ssl.auto-trust.enabled=true and add this host to ssl.auto-trust.domains");
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        System.out.println(line(60));
    }

    /**
     * Returns {@code true} if the TLS cert chain for {@code host:port} appears
     * to be replaced by a corporate proxy (ZScaler, Cisco, Netskope, etc.).
     * Detection: leaf cert issuer contains known proxy vendor names.
     */
    public static boolean isProxyIntercepting(String host, int port) {
        List<X509Certificate> chain = SslCertificateUtils.fetchChain(host, port);
        if (chain.isEmpty()) return false;
        return SslCertificateUtils.isIssuedByProxy(chain.get(0),
                "zscaler", "cisco", "netskope", "palo alto", "broadcom",
                "symantec", "bluecoat", "mcafee", "forcepoint", "cloudflare gateway");
    }

    /** Prints all response headers for {@code urlStr} to stdout (no body). */
    public static void printHeaders(String urlStr) {
        System.out.println("\nHeaders for " + urlStr);
        try {
            HttpURLConnection conn = open(urlStr, 10_000);
            conn.getResponseCode();
            for (Map.Entry<String, List<String>> h : conn.getHeaderFields().entrySet()) {
                System.out.println("  " + (h.getKey() == null ? "(Status-Line)" : h.getKey())
                        + ": " + h.getValue());
            }
            conn.disconnect();
        } catch (Exception e) {
            System.out.println("  ERROR: " + e.getMessage());
        }
    }

    /**
     * Returns {@code true} if a plain TCP connection to {@code host:port}
     * succeeds within {@code timeoutMs}. Does NOT perform TLS handshake.
     */
    public static boolean isReachable(String host, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) { return false; }
    }

    /** Prints all resolved IP addresses for {@code hostname} to stdout. */
    public static void printDnsInfo(String hostname) {
        System.out.println("\nDNS — " + hostname);
        try {
            for (InetAddress a : InetAddress.getAllByName(hostname)) {
                System.out.println("  " + a.getHostAddress());
            }
        } catch (UnknownHostException e) {
            System.out.println("  [UNRESOLVABLE] " + e.getMessage());
        }
    }

    /**
     * Prints current JVM HTTP/HTTPS proxy settings from System properties.
     * Shows http.proxyHost, https.proxyHost, http.nonProxyHosts, socksProxyHost.
     */
    public static void printProxySettings() {
        System.out.println("\nJVM proxy settings:");
        String[] keys = { "http.proxyHost", "http.proxyPort",
                "https.proxyHost", "https.proxyPort", "http.nonProxyHosts",
                "socksProxyHost", "socksProxyPort", "java.net.useSystemProxies" };
        boolean any = false;
        for (String k : keys) {
            String v = System.getProperty(k);
            if (v != null) { System.out.println("  " + k + " = " + v); any = true; }
        }
        if (!any) System.out.println("  (no JVM proxy system properties set)");
    }

    private static HttpURLConnection open(String urlStr, int timeoutMs) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(urlStr).openConnection();
        c.setConnectTimeout(timeoutMs);
        c.setReadTimeout(timeoutMs);
        c.setRequestMethod("GET");
        c.setRequestProperty("User-Agent", "ssl-auto-trust/1.0 Java/" + System.getProperty("java.version"));
        c.setRequestProperty("Accept", "*/*");
        return c;
    }

    private static String readAtMost(InputStream is, int max) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line; int total = 0;
        while ((line = br.readLine()) != null && total < max) {
            sb.append(line).append("\n"); total += line.length();
        }
        br.close();
        return sb.toString();
    }

    private static String line(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append("─");
        return sb.toString();
    }
}
