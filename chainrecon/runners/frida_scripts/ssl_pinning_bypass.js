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
    const init = SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
    init.implementation = function (keyManagers, trustManagers, secureRandom) {
      console.log("[SSL-BYPASS] Replacing SSLContext TrustManagers");
      return init.call(this, keyManagers, [TrustAll.$new()], secureRandom);
    };
    console.log("[+] SSLContext TrustManager replacement installed");
  } catch (e) {
    console.log("[-] X509TrustManager bypass failed: " + e);
  }

  // 2. OkHttp3 CertificatePinner
  try {
    const Pinner = Java.use("okhttp3.CertificatePinner");
    Pinner.check.overloads.forEach(function (overload) {
      overload.implementation = function () {
        console.log("[SSL-BYPASS] OkHttp3 CertificatePinner.check bypassed for " + arguments[0]);
        return;
      };
    });
    console.log("[+] OkHttp3 CertificatePinner bypassed");
  } catch (e) {
    console.log("[-] OkHttp3 CertificatePinner not found (OK if app doesn't use OkHttp)");
  }

  // 3. Hostname Verifier
  try {
    const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    const TrustAllHostnameVerifier = Java.registerClass({
      name: "com.chainrecon.TrustAllHostnameVerifier",
      implements: [HostnameVerifier],
      methods: {
        verify: function (hostname, session) {
          console.log("[SSL-BYPASS] HostnameVerifier accepted " + hostname);
          return true;
        }
      }
    });
    const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    const setDefaultHostnameVerifier = HttpsURLConnection.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
    setDefaultHostnameVerifier.implementation = function (verifier) {
      console.log("[SSL-BYPASS] Replacing default HostnameVerifier");
      return setDefaultHostnameVerifier.call(this, TrustAllHostnameVerifier.$new());
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
