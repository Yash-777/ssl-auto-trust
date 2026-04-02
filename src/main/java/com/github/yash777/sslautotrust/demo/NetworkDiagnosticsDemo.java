package com.github.yash777.sslautotrust.demo;

import com.github.yash777.sslautotrust.util.HttpConnectionUtils;
import com.github.yash777.sslautotrust.util.SslCertificateUtils;

import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;

/**
 * NetworkDiagnosticsDemo
 *
 * <p>Exercises every method in {@link SslCertificateUtils} and
 * {@link HttpConnectionUtils}. Run this first to diagnose your
 * network + ZScaler configuration before enabling the starter.
 */
public class NetworkDiagnosticsDemo {

    private static final List<String> PROBE_HOSTS = Arrays.asList(
        "github.com",
        "api.github.com",
        "marketplace.eclipse.org",
        "azuredownloads-g3ahgwb5b8bkbxhd.b01.azurefd.net"
    );

    public static void main(String[] args) throws Exception {
        // 1. JVM proxy settings
        HttpConnectionUtils.printProxySettings();

        // 2. DNS resolution per host
        for (String host : PROBE_HOSTS) {
            HttpConnectionUtils.printDnsInfo(host);
        }

        // 3. TCP reachability (socket only, no TLS)
        System.out.println("\nTCP reachability (port 443, 5s timeout):");
        for (String host : PROBE_HOSTS) {
            boolean up = HttpConnectionUtils.isReachable(host, 443, 5_000);
            System.out.println("  " + (up ? "[UP]     " : "[BLOCKED]") + " " + host);
        }

        // 4. Proxy interception detection
        System.out.println("\nProxy interception detection:");
        for (String host : PROBE_HOSTS) {
            System.out.println("  " + host + " → "
                    + (HttpConnectionUtils.isProxyIntercepting(host, 443)
                       ? "PROXY INTERCEPTING (ZScaler/corporate CA detected)"
                       : "direct / no interception detected"));
        }

        // 5. Full cert chains
        System.out.println("\nCertificate chains:");
        for (String host : PROBE_HOSTS) {
            SslCertificateUtils.printCertChain(host, 443);
        }

        // 6. Expiry warnings (30-day threshold)
        System.out.println("\nExpiry warnings:");
        for (String host : PROBE_HOSTS) {
            SslCertificateUtils.printExpiryWarnings(
                SslCertificateUtils.fetchChain(host, 443), 30);
        }

        // 7. JVM cacerts summary
        KeyStore cacerts = SslCertificateUtils.loadJvmCacerts();
        System.out.println("\nJVM cacerts: " + cacerts.size() + " entries");
        // SslCertificateUtils.listAliases(cacerts, "cacerts"); // uncomment to list all

        // 8. HTTP GET demo (needs ZScaler certs trusted first)
        HttpConnectionUtils.get("https://api.github.com/", 10_000);
    }
}
