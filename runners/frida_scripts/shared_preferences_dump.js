/*
 * shared_preferences_dump.js — Dump SharedPreferences on Android
 *
 * Hooks android.content.SharedPreferences to log all getXxx / putXxx calls
 * and optionally dump the full contents of each preferences file.
 */

Java.perform(function () {
    var SP = Java.use("android.app.SharedPreferencesImpl");

    // --- Log reads --------------------------------------------------------
    var getters = ["getString", "getInt", "getLong", "getFloat", "getBoolean"];
    getters.forEach(function (name) {
        try {
            SP[name].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var key = arguments[0];
                    var result = this[name].apply(this, arguments);
                    console.log("[SharedPrefs GET] " + name + "(" + key + ") => " + result);
                    return result;
                };
            });
        } catch (e) {
            // Method may not exist on all API levels
        }
    });

    // --- Log writes -------------------------------------------------------
    var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    var putters = ["putString", "putInt", "putLong", "putFloat", "putBoolean"];
    putters.forEach(function (name) {
        try {
            Editor[name].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var key = arguments[0];
                    var val = arguments[1];
                    console.log("[SharedPrefs PUT] " + name + "(" + key + ", " + val + ")");
                    return this[name].apply(this, arguments);
                };
            });
        } catch (e) {}
    });

    // --- Dump all prefs on load -------------------------------------------
    try {
        var Context = Java.use("android.app.ContextImpl");
        Context.getSharedPreferences.overload("java.lang.String", "int").implementation = function (name, mode) {
            var sp = this.getSharedPreferences(name, mode);
            console.log("\n[SharedPrefs OPEN] " + name);
            try {
                var all = sp.getAll();
                var it = all.entrySet().iterator();
                while (it.hasNext()) {
                    var entry = it.next();
                    console.log("  " + entry.getKey() + " = " + entry.getValue());
                }
            } catch (e) {
                console.log("  (could not dump entries)");
            }
            return sp;
        };
    } catch (e) {}

    console.log("[*] SharedPreferences hooks installed");
});
