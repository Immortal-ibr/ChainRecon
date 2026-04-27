Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const keyFilter = (config.key_filter || "").toLowerCase();

  const shouldLog = function (text) {
    const normalized = String(text || "").toLowerCase();
    return !keyFilter || normalized.indexOf(keyFilter) !== -1;
  };

  try {
    const Context = Java.use("android.app.ContextImpl");
    Context.getSharedPreferences.overload("java.lang.String", "int").implementation = function (name, mode) {
      const prefs = this.getSharedPreferences(name, mode);
      if (shouldLog(name)) {
        console.log("[RUNTIME-PREF] open " + name);
      }
      return prefs;
    };
    console.log("[HOOK] ContextImpl.getSharedPreferences");
  } catch (e) {
    console.log("[WARN] SharedPreferences open hook unavailable");
  }

  try {
    const Base64 = Java.use("android.util.Base64");
    Base64.decode.overload("java.lang.String", "int").implementation = function (text, flags) {
      if (shouldLog(text)) {
        console.log("[RUNTIME-BASE64] decode " + text);
      }
      return this.decode(text, flags);
    };
    console.log("[HOOK] android.util.Base64.decode");
  } catch (e) {
    console.log("[WARN] Base64 decode hook unavailable");
  }

  console.log("[STATUS] nooie runtime config ready");
});
