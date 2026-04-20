/*
 * http_intercept.js — Intercept HTTP/HTTPS requests and responses
 *
 * Hooks OkHttp, HttpURLConnection, and WebView to log URLs, headers,
 * methods, and bodies.  Reveals plaintext traffic and API patterns.
 */

Java.perform(function () {

    // --- OkHttp3 Interceptor (most IoT apps) ------------------------------
    try {
        var Interceptor = Java.use("okhttp3.Interceptor");
        var OkHttpClient$Builder = Java.use("okhttp3.OkHttpClient$Builder");

        var MyInterceptor = Java.registerClass({
            name: "com.chainrecon.HttpInterceptor",
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    var request = chain.request();
                    console.log("[OkHttp] " + request.method() + " " + request.url());

                    // Log request headers
                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        console.log("  > " + headers.name(i) + ": " + headers.value(i));
                    }

                    var response = chain.proceed(request);
                    console.log("[OkHttp] Response: " + response.code() + " " + response.message());
                    return response;
                }
            }
        });

        OkHttpClient$Builder.build.implementation = function () {
            this.addInterceptor(MyInterceptor.$new());
            console.log("[*] OkHttp interceptor injected");
            return this.build();
        };
    } catch (e) {
        console.log("[!] OkHttp3 not found, skipping");
    }

    // --- HttpURLConnection ------------------------------------------------
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var conn = this.openConnection();
            console.log("[URLConnection] " + this.toString());
            return conn;
        };
    } catch (e) {}

    // --- WebView.loadUrl --------------------------------------------------
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            console.log("[WebView] loadUrl: " + url);
            return this.loadUrl(url);
        };
        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            console.log("[WebView] loadUrl: " + url + " headers=" + headers);
            return this.loadUrl(url, headers);
        };
    } catch (e) {}

    // --- Retrofit (log service interface calls) ---------------------------
    try {
        var Retrofit$Builder = Java.use("retrofit2.Retrofit$Builder");
        Retrofit$Builder.baseUrl.overload("java.lang.String").implementation = function (url) {
            console.log("[Retrofit] baseUrl: " + url);
            return this.baseUrl(url);
        };
    } catch (e) {}

    console.log("[*] HTTP intercept hooks installed");
});
