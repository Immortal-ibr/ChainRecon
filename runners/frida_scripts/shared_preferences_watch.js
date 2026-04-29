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

  const hookAdditionalClasses = function () {
    const classes = Array.isArray(config.additional_classes) ? config.additional_classes : [];
    const interesting = /get|put|set|save|commit|apply|token|pref|config/i;
    classes.forEach(function (className) {
      try {
        const clazz = Java.use(className);
        const methods = clazz.class.getDeclaredMethods();
        const seen = {};
        let count = 0;
        for (let i = 0; i < methods.length; i++) {
          const methodName = methods[i].getName();
          if (seen[methodName] || !interesting.test(methodName) || !clazz[methodName]) continue;
          seen[methodName] = true;
          clazz[methodName].overloads.forEach(function (ov) {
            ov.implementation = function () {
              const args = [];
              for (let j = 0; j < arguments.length; j++) args.push(describeValue(arguments[j]));
              if (!args.length || args.some(function (arg) { return shouldLog(arg); })) {
                console.log("[PREF-EXTRA] " + className + "." + methodName + "(" + args.join(", ") + ")");
              }
              return ov.apply(this, arguments);
            };
            count += 1;
          });
        }
        console.log("[HOOK] " + className + " preferences extra overloads=" + count);
      } catch (e) {
        console.log("[WARN] Preferences extra class hook failed for " + className + ": " + e);
      }
    });
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

  hookAdditionalClasses();
  console.log("[STATUS] shared preferences watch ready");
});
