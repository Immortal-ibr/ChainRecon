/**
 * Bypass common SSL/TLS certificate pinning implementations on Android.
 *
 * Covers:
 *  - TrustManagerFactory / X509TrustManager (standard Java)
 *  - OkHttp3 CertificatePinner
 *  - Conscrypt / Okhostname verifier
 *  - Android WebView
 *
 * Usage:  frida -U -n <app> -l ssl_pinning_bypass.js
 */
Java.perform(function () {
  console.log("[*] SSL Pinning Bypass loaded");

  // 1. Override X509TrustManager to trust all certificates
  try {
    const X509TM = Java.use("javax.net.ssl.X509TrustManager");
    const TrustAll = Java.registerClass({
      name: "com.chainrecon.TrustAll",
      implements: [X509TM],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () { return []; }
      }
    });

    const SSLContext = Java.use("javax.net.ssl.SSLContext");
    const ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustAll.$new()], null);
    console.log("[+] X509TrustManager bypassed");
  } catch (e) {
    console.log("[-] X509TrustManager bypass failed: " + e);
  }

  // 2. OkHttp3 CertificatePinner
  try {
    const Pinner = Java.use("okhttp3.CertificatePinner");
    Pinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
      console.log("[+] OkHttp3 CertificatePinner.check bypassed for " + arguments[0]);
    };
    console.log("[+] OkHttp3 CertificatePinner bypassed");
  } catch (e) {
    console.log("[-] OkHttp3 CertificatePinner not found (OK if app doesn't use OkHttp)");
  }

  // 3. Hostname Verifier
  try {
    const HV = Java.use("javax.net.ssl.HttpsURLConnection");
    HV.setDefaultHostnameVerifier.implementation = function (verifier) {
      console.log("[+] HostnameVerifier.setDefault bypassed");
    };
  } catch (e) {
    console.log("[-] HostnameVerifier bypass skipped");
  }

  // 4. WebViewClient SSL error handler
  try {
    const WVC = Java.use("android.webkit.WebViewClient");
    WVC.onReceivedSslError.implementation = function (view, handler, error) {
      console.log("[+] WebViewClient SSL error bypassed");
      handler.proceed();
    };
  } catch (e) {
    console.log("[-] WebViewClient bypass skipped");
  }

  console.log("[*] SSL Pinning Bypass complete");
});
