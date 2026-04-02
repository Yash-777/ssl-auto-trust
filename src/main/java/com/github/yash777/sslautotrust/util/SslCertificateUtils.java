package com.github.yash777.sslautotrust.util;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

/**
 * SslCertificateUtils
 *
 * <p>Standalone SSL/TLS certificate inspection utilities. Zero Spring dependencies.
 * Use in plain Java mains, unit tests, or Spring components.
 *
 * <pre>{@code
 * // Print full cert chain for any HTTPS host
 * SslCertificateUtils.printCertChain("github.com", 443);
 *
 * // Check for expiring certs
 * SslCertificateUtils.printExpiryWarnings(
 *     SslCertificateUtils.fetchChain("myhost.com", 443), 30);
 *
 * // Detect ZScaler / corporate proxy interception
 * boolean intercepted = SslCertificateUtils.isIssuedByProxy(chain.get(0), "zscaler");
 *
 * // Convert to PEM string
 * String pem = SslCertificateUtils.toPem(chain.get(0));
 *
 * // Load JVM cacerts
 * KeyStore ks = SslCertificateUtils.loadJvmCacerts();
 * }</pre>
 */
public final class SslCertificateUtils {

    private SslCertificateUtils() {}

    /**
     * Fetches the full TLS certificate chain from {@code host:port} using a
     * temporary trust-all handshake. Returns an empty list on any network error.
     */
    public static List<X509Certificate> fetchChain(String host, int port) {
        List<X509Certificate> chain = new ArrayList<X509Certificate>();
        try {
            final X509Certificate[][] holder = new X509Certificate[1][];
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) { holder[0] = c; }
                public X509Certificate[] getAcceptedIssuers() {
                    return holder[0] != null ? holder[0] : new X509Certificate[0];
                }
            }}, new SecureRandom());
            SSLSocket sock = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
            try {
                sock.setSoTimeout(10_000);
                sock.startHandshake();
                for (Certificate c : sock.getSession().getPeerCertificates()) {
                    if (c instanceof X509Certificate) chain.add((X509Certificate) c);
                }
            } finally {
                try { sock.close(); } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            System.err.println("[SslCertificateUtils] fetchChain(" + host + ":" + port + "): " + e.getMessage());
        }
        return chain;
    }

    /** Prints subject, issuer, serial, validity, and signature algorithm for each cert in chain. */
    public static void printCertChain(String host, int port) {
        System.out.println("Certificate chain — " + host + ":" + port);
        System.out.println(line(60));
        List<X509Certificate> chain = fetchChain(host, port);
        if (chain.isEmpty()) { System.out.println("  [ERROR] Could not fetch chain."); return; }
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            String role = i == 0 ? "Leaf (server)" : i == chain.size() - 1 ? "Root CA" : "Intermediate CA";
            System.out.println("  cert[" + i + "] " + role);
            System.out.println("    Subject : " + c.getSubjectDN().getName());
            System.out.println("    Issuer  : " + c.getIssuerDN().getName());
            System.out.println("    Serial  : " + c.getSerialNumber().toString(16).toUpperCase());
            System.out.println("    Valid   : " + c.getNotBefore() + "  to  " + c.getNotAfter());
            System.out.println("    SigAlg  : " + c.getSigAlgName());
        }
        System.out.println(line(60));
    }

    /**
     * Prints a warning to stderr for any cert in the chain that expires
     * within {@code warnDays} days.
     */
    public static void printExpiryWarnings(List<X509Certificate> chain, int warnDays) {
        long warnMs = (long) warnDays * 24 * 60 * 60 * 1000L;
        long now = System.currentTimeMillis();
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            long rem = c.getNotAfter().getTime() - now;
            if (rem < 0) {
                System.err.println("[EXPIRED] cert[" + i + "] " + c.getSubjectDN().getName());
            } else if (rem < warnMs) {
                System.err.println("[EXPIRY-WARN] cert[" + i + "] expires in "
                        + rem / (24 * 60 * 60 * 1000) + " days — " + c.getSubjectDN().getName());
            }
        }
    }

    /** Converts an X509Certificate to PEM-encoded string. */
    public static String toPem(X509Certificate cert) {
        try {
            byte[] enc = cert.getEncoded();
            return "-----BEGIN CERTIFICATE-----\n"
                    + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(enc)
                    + "\n-----END CERTIFICATE-----\n";
        } catch (CertificateEncodingException e) {
            return null;
        }
    }

    /**
     * Returns {@code true} if the cert's issuer DN contains any of the given keywords.
     * Useful for detecting corporate proxy CAs (ZScaler, Cisco, Netskope, etc.).
     * Case-insensitive match.
     */
    public static boolean isIssuedByProxy(X509Certificate cert, String... keywords) {
        String issuer = cert.getIssuerDN().getName().toLowerCase(Locale.ROOT);
        for (String kw : keywords) {
            if (issuer.contains(kw.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    /** Loads the JVM default cacerts KeyStore. Works on Java 8 and Java 11+. */
    public static KeyStore loadJvmCacerts() throws Exception {
        String home = System.getProperty("java.home");
        File f = new File(home, "lib/security/cacerts");
        if (!f.exists()) f = new File(home, "jre/lib/security/cacerts");
        if (!f.exists()) throw new FileNotFoundException("cacerts not found under " + home);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(f)) { ks.load(fis, "changeit".toCharArray()); }
        return ks;
    }

    /** Prints all aliases in the KeyStore to stdout. */
    public static void listAliases(KeyStore ks, String label) throws KeyStoreException {
        System.out.println("KeyStore — " + label + " (" + ks.size() + " entries):");
        Enumeration<String> a = ks.aliases();
        while (a.hasMoreElements()) System.out.println("  " + a.nextElement());
    }

    private static String line(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append("─");
        return sb.toString();
    }
}
