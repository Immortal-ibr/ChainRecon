Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const hostFilter = String(config.host_filter || "").toLowerCase();

  const shouldLog = function (text) {
    const normalized = String(text || "").toLowerCase();
    return !hostFilter || hostFilter === "*" || normalized.indexOf(hostFilter) !== -1;
  };

  const logLine = function (tag, text) {
    if (shouldLog(text)) {
      console.log("[" + tag + "] " + text);
    }
  };

  try {
    const RequestBuilder = Java.use("okhttp3.Request$Builder");
    const overloads = [
      ["url", ["java.lang.String"]],
      ["url", ["java.net.URL"]],
    ];
    overloads.forEach(function (item) {
      try {
        const ov = RequestBuilder[item[0]].overload.apply(RequestBuilder[item[0]], item[1]);
        ov.implementation = function () {
          logLine("HTTP-BUILD", "Request.Builder.url " + arguments[0]);
          return ov.apply(this, arguments);
        };
      } catch (e) {}
    });
    console.log("[HOOK] okhttp3.Request.Builder.url");
  } catch (e) {
    console.log("[WARN] OkHttp Request.Builder hook unavailable: " + e);
  }

  try {
    const OkHttpClient = Java.use("okhttp3.OkHttpClient");
    const newCall = OkHttpClient.newCall.overload("okhttp3.Request");
    newCall.implementation = function (request) {
      const url = request.url().toString();
      logLine("HTTP-REQ", request.method() + " " + url);
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
        logLine("HTTP-RESP", responseCode + " " + this.request().url().toString());
      } catch (e) {}
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
      logLine("HTTP-REQ", "URL.openConnection " + this.toString());
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
        logLine("HTTP-RESP", responseCode + " " + this.getURL().toString());
      } catch (e) {}
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
      logLine("WEBVIEW", url);
      return loadUrl.call(this, url);
    };
    console.log("[HOOK] android.webkit.WebView.loadUrl");
  } catch (e) {
    console.log("[WARN] WebView hook unavailable: " + e);
  }

  console.log("[STATUS] http trace ready");
});
