/*
 * certificate_pinning_detect.js — Detect certificate-pinning implementations
 *
 * Hooks common pinning APIs to identify which libraries and techniques the
 * target app uses.  Does NOT bypass pinning (use ssl_pinning_bypass.js for that).
 */

Java.perform(function () {
    var findings = [];

    function record(lib, detail) {
        var msg = "[PinDetect] " + lib + ": " + detail;
        console.log(msg);
        findings.push({ library: lib, detail: detail });
    }

    // --- OkHttp CertificatePinner -----------------------------------------
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCerts) {
            record("OkHttp3", "CertificatePinner.check hostname=" + hostname);
            return this.check(hostname, peerCerts);
        };
    } catch (e) {}

    try {
        var CertPinnerOld = Java.use("com.squareup.okhttp.CertificatePinner");
        CertPinnerOld.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCerts) {
            record("OkHttp2", "CertificatePinner.check hostname=" + hostname);
            return this.check(hostname, peerCerts);
        };
    } catch (e) {}

    // --- Android Network Security Config ----------------------------------
    try {
        var PinSet = Java.use("android.security.net.config.PinSet");
        record("NetworkSecurityConfig", "PinSet class present in runtime");
    } catch (e) {}

    // --- TrustManagerImpl (system-level) -----------------------------------
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function () {
            record("Conscrypt", "TrustManagerImpl.verifyChain invoked");
            return this.verifyChain.apply(this, arguments);
        };
    } catch (e) {}

    // --- Apache HttpClient (legacy) ----------------------------------------
    try {
        var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function (host, cns, sa, strict) {
            record("ApacheHTTP", "AbstractVerifier.verify host=" + host + " strict=" + strict);
            return this.verify(host, cns, sa, strict);
        };
    } catch (e) {}

    // --- TrustKit (popular iOS/Android pinning library) --------------------
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
        record("TrustKit", "TrustKit class loaded — pinning library detected");
    } catch (e) {}

    // --- Custom X509TrustManager ------------------------------------------
    try {
        var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var X509 = Java.use("javax.net.ssl.X509ExtendedTrustManager");
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (name.indexOf("TrustManager") !== -1 || name.indexOf("PinningTrustManager") !== -1) {
                    record("Custom", "Custom TrustManager class: " + name);
                }
            },
            onComplete: function () {}
        });
    } catch (e) {}

    // --- Summary after short delay ----------------------------------------
    setTimeout(function () {
        console.log("\n========== Pinning Detection Summary ==========");
        if (findings.length === 0) {
            console.log("No certificate-pinning implementations detected.");
        } else {
            console.log("Found " + findings.length + " pinning indicator(s):");
            findings.forEach(function (f) {
                console.log("  [" + f.library + "] " + f.detail);
            });
        }
        console.log("===============================================\n");
    }, 3000);

    console.log("[*] Certificate-pinning detection hooks installed");
});
