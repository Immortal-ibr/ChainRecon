Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const rawFilter = config.class_filter || "";
  const filters = Array.isArray(rawFilter)
    ? rawFilter.map(function (item) { return String(item || "").toLowerCase(); }).filter(Boolean)
    : String(rawFilter || "").toLowerCase().split(/[,\n;]+/).map(function (item) { return item.trim(); }).filter(Boolean);
  const maxEventsPerSecond = Math.max(parseInt(config.max_events_per_second || "50", 10) || 50, 1);
  const seen = {};
  let windowStarted = Date.now();
  let eventsThisWindow = 0;
  let dropped = 0;

  const normalize = function (name) {
    let value = String(name || "");
    while (value.startsWith("[")) value = value.substring(1);
    if (value.startsWith("L") && value.endsWith(";")) value = value.substring(1, value.length - 1);
    return value;
  };

  const matches = function (name) {
    const lowered = String(name || "").toLowerCase();
    return !filters.length || filters.indexOf("*") !== -1 || filters.some(function (filter) {
      return lowered.indexOf(filter) !== -1;
    });
  };

  const emit = function (tag, line) {
    const now = Date.now();
    if (now - windowStarted >= 1000) {
      if (dropped > 0) {
        console.log("[DROPPED] live_class_monitor dropped_event_count=" + dropped);
        dropped = 0;
      }
      windowStarted = now;
      eventsThisWindow = 0;
    }
    if (eventsThisWindow >= maxEventsPerSecond) {
      dropped += 1;
      return;
    }
    eventsThisWindow += 1;
    console.log("[" + tag + "] " + line);
  };

  const recordClass = function (tag, rawName, detail) {
    const name = normalize(rawName);
    if (!name || !matches(name)) return;
    const key = tag + ":" + name + ":" + String(detail || "");
    if (tag === "CLASS-LOAD" && seen[name]) return;
    seen[name] = true;
    emit(tag, name + (detail ? " " + detail : ""));
  };

  Java.enumerateLoadedClasses({
    onMatch(name) {
      const normalized = normalize(name);
      if (!normalized || !matches(normalized)) return;
      seen[normalized] = true;
      emit("CLASS-SEED", normalized);
    },
    onComplete() {
      console.log("[STATUS] live class monitor seeded classes=" + Object.keys(seen).length);
    }
  });

  try {
    const ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overloads.forEach(function (ov) {
      ov.implementation = function () {
        const result = ov.apply(this, arguments);
        try {
          recordClass("CLASS-LOAD", arguments[0], "loader=" + this.toString());
        } catch (e) {}
        return result;
      };
    });
    console.log("[HOOK] java.lang.ClassLoader.loadClass");
  } catch (e) {
    console.log("[WARN] ClassLoader.loadClass hook unavailable: " + e);
  }

  try {
    const Class = Java.use("java.lang.Class");
    Class.forName.overloads.forEach(function (ov) {
      ov.implementation = function () {
        const result = ov.apply(this, arguments);
        try {
          recordClass("CLASS-FORNAME", arguments[0], "");
        } catch (e) {}
        return result;
      };
    });
    console.log("[HOOK] java.lang.Class.forName");
  } catch (e) {
    console.log("[WARN] Class.forName hook unavailable: " + e);
  }

  console.log("[STATUS] live loaded class monitor ready");
});
