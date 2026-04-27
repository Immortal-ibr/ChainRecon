Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const keyFilter = (config.key_filter || "").toLowerCase();

  const shouldLog = function (key) {
    const normalized = String(key || "").toLowerCase();
    return !keyFilter || normalized.indexOf(keyFilter) !== -1;
  };

  const describeValue = function (value) {
    try {
      if (value === null || value === undefined) return "null";
      return value.toString();
    } catch (e) {
      return "<?>";
    }
  };

  const SP = Java.use("android.app.SharedPreferencesImpl");
  ["getString", "getInt", "getLong", "getFloat", "getBoolean"].forEach(function (name) {
    try {
      SP[name].overloads.forEach(function (overload) {
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

  const Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
  ["putString", "putInt", "putLong", "putFloat", "putBoolean"].forEach(function (name) {
    try {
      Editor[name].overloads.forEach(function (overload) {
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

  console.log("[STATUS] shared preferences monitor ready");
});
