Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const keyFilter = String(config.key_filter || "").toLowerCase();

  const shouldLog = function (key) {
    const normalized = String(key || "").toLowerCase();
    return !keyFilter || keyFilter === "*" || normalized.indexOf(keyFilter) !== -1;
  };

  const describeValue = function (value) {
    try {
      if (value === null || value === undefined) return "null";
      return value.toString();
    } catch (e) {
      return "<?>";
    }
  };

  try {
    const SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    ["getString", "getInt", "getLong", "getFloat", "getBoolean"].forEach(function (name) {
      try {
        SharedPreferencesImpl[name].overloads.forEach(function (overload) {
          overload.implementation = function () {
            const key = arguments[0];
            const result = overload.apply(this, arguments);
            if (shouldLog(key)) {
              console.log("[PREF-GET] " + key + " => " + describeValue(result));
            }
            return result;
          };
        });
      } catch (e) {}
    });
    console.log("[HOOK] android.app.SharedPreferencesImpl");
  } catch (e) {
    console.log("[WARN] SharedPreferencesImpl read hook unavailable: " + e);
  }

  try {
    const EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    ["putString", "putInt", "putLong", "putFloat", "putBoolean"].forEach(function (name) {
      try {
        EditorImpl[name].overloads.forEach(function (overload) {
          overload.implementation = function () {
            const key = arguments[0];
            const value = arguments[1];
            if (shouldLog(key)) {
              console.log("[PREF-PUT] " + key + " => " + describeValue(value));
            }
            return overload.apply(this, arguments);
          };
        });
      } catch (e) {}
    });
    console.log("[HOOK] android.app.SharedPreferencesImpl$EditorImpl");
  } catch (e) {
    console.log("[WARN] SharedPreferencesImpl editor hook unavailable: " + e);
  }

  console.log("[STATUS] shared preferences watch ready");
});
