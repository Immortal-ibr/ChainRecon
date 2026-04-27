Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const hostFilter = (config.host_filter || "").toLowerCase();

  const shouldLog = function (text) {
    const normalized = String(text || "").toLowerCase();
    return !hostFilter || normalized.indexOf(hostFilter) !== -1;
  };

  const emit = function (tag, details) {
    if (shouldLog(details)) {
      console.log("[" + tag + "] " + details);
    }
  };

  try {
    const URL = Java.use("java.net.URL");
    const openConnection = URL.openConnection.overload();
    openConnection.implementation = function () {
      const url = this.toString();
      emit("URL", url);
      return openConnection.call(this);
    };
    console.log("[HOOK] java.net.URL.openConnection");
  } catch (e) {
    console.log("[WARN] URL hook unavailable: " + e);
  }

  try {
    const OkClient = Java.use("okhttp3.OkHttpClient");
    const newCall = OkClient.newCall.overload("okhttp3.Request");
    newCall.implementation = function (request) {
      const url = request.url().toString();
      if (shouldLog(url)) {
        console.log("[HTTP] " + request.method() + " " + url);
      }
      return newCall.call(this, request);
    };
    console.log("[HOOK] okhttp3.OkHttpClient.newCall");
  } catch (e) {
    console.log("[WARN] OkHttp hook unavailable");
  }

  try {
    const Socket = Java.use("java.net.Socket");
    const connect = Socket.connect.overload("java.net.SocketAddress", "int");
    connect.implementation = function (addr, timeout) {
      emit("TCP", addr + " timeout=" + timeout);
      return connect.call(this, addr, timeout);
    };
    console.log("[HOOK] java.net.Socket.connect");
  } catch (e) {
    console.log("[WARN] Socket hook unavailable: " + e);
  }

  console.log("[STATUS] network monitor ready");
});
