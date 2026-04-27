Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const hostFilter = (config.host_filter || "").toLowerCase();

  const shouldLog = function (text) {
    const normalized = String(text || "").toLowerCase();
    return !hostFilter || normalized.indexOf(hostFilter) !== -1;
  };

  try {
    const OkHttpClient = Java.use("okhttp3.OkHttpClient");
    const newCall = OkHttpClient.newCall.overload("okhttp3.Request");
    newCall.implementation = function (request) {
      const url = request.url().toString();
      if (shouldLog(url)) {
        console.log("[HTTP-REQ] " + request.method() + " " + url);
      }
      return newCall.call(this, request);
    };
    console.log("[HOOK] okhttp3.OkHttpClient.newCall");
  } catch (e) {
    console.log("[WARN] OkHttp request hook unavailable: " + e);
  }

  try {
    const Response = Java.use("okhttp3.Response");
    const code = Response.code.overload();
    code.implementation = function () {
      const responseCode = code.call(this);
      try {
        const url = this.request().url().toString();
        if (shouldLog(url)) {
          console.log("[HTTP-RESP] " + responseCode + " " + url);
        }
      } catch (e) {
      }
      return responseCode;
    };
    console.log("[HOOK] okhttp3.Response.code");
  } catch (e) {
    console.log("[WARN] OkHttp response hook unavailable: " + e);
  }

  try {
    const URL = Java.use("java.net.URL");
    const openConnection = URL.openConnection.overload();
    openConnection.implementation = function () {
      const url = this.toString();
      if (shouldLog(url)) {
        console.log("[HTTP-REQ] URL.openConnection " + url);
      }
      return openConnection.call(this);
    };
    console.log("[HOOK] java.net.URL.openConnection");
  } catch (e) {
    console.log("[WARN] URLConnection hook unavailable: " + e);
  }

  try {
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    const getResponseCode = HttpURLConnection.getResponseCode.overload();
    getResponseCode.implementation = function () {
      const responseCode = getResponseCode.call(this);
      try {
        const url = this.getURL().toString();
        if (shouldLog(url)) {
          console.log("[HTTP-RESP] " + responseCode + " " + url);
        }
      } catch (e) {
      }
      return responseCode;
    };
    console.log("[HOOK] java.net.HttpURLConnection.getResponseCode");
  } catch (e) {
    console.log("[WARN] HttpURLConnection response hook unavailable: " + e);
  }

  try {
    const WebView = Java.use("android.webkit.WebView");
    const loadUrl = WebView.loadUrl.overload("java.lang.String");
    loadUrl.implementation = function (url) {
      if (shouldLog(url)) {
        console.log("[WEBVIEW] " + url);
      }
      return loadUrl.call(this, url);
    };
    console.log("[HOOK] android.webkit.WebView.loadUrl");
  } catch (e) {
    console.log("[WARN] WebView hook unavailable");
  }

  console.log("[STATUS] http intercept ready");
});
