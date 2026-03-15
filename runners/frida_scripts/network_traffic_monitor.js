/**
 * Monitor network-related API calls from the app.
 *
 * Hooks:
 *  - java.net.URL.openConnection
 *  - okhttp3.OkHttpClient.newCall (if available)
 *  - java.net.Socket.connect
 *
 * Usage:  frida -U -n <app> -l network_traffic_monitor.js
 */
Java.perform(function () {
  console.log("[*] Network Traffic Monitor loaded");

  // 1. java.net.URL.openConnection
  try {
    const URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
      console.log("[HTTP] URL.openConnection -> " + this.toString());
      return this.openConnection();
    };
    console.log("[+] Hooked URL.openConnection");
  } catch (e) {
    console.log("[-] URL.openConnection hook failed: " + e);
  }

  // 2. OkHttp3 newCall
  try {
    const OkClient = Java.use("okhttp3.OkHttpClient");
    OkClient.newCall.implementation = function (request) {
      console.log("[HTTP] OkHttp3.newCall -> " + request.url().toString());
      console.log("       Method: " + request.method());
      const headers = request.headers();
      for (let i = 0; i < headers.size(); i++) {
        console.log("       " + headers.name(i) + ": " + headers.value(i));
      }
      return this.newCall(request);
    };
    console.log("[+] Hooked OkHttp3.newCall");
  } catch (e) {
    console.log("[-] OkHttp3 not found (OK if app doesn't use it)");
  }

  // 3. Socket.connect
  try {
    const Socket = Java.use("java.net.Socket");
    Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (addr, timeout) {
      console.log("[TCP] Socket.connect -> " + addr.toString() + " (timeout=" + timeout + "ms)");
      return this.connect(addr, timeout);
    };
    console.log("[+] Hooked Socket.connect");
  } catch (e) {
    console.log("[-] Socket.connect hook failed: " + e);
  }

  console.log("[*] Network Traffic Monitor ready");
});
