Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const rawFilter = config.class_filter || config.target_filter || "";
  const filters = Array.isArray(rawFilter)
    ? rawFilter.map(function (item) { return String(item || "").toLowerCase(); }).filter(Boolean)
    : String(rawFilter || "").toLowerCase().split(/[,\n;]+/).map(function (item) { return item.trim(); }).filter(Boolean);
  const classes = [];
  const seen = {};

  const normalize = function (name) {
    let value = String(name || "");
    while (value.startsWith("[")) {
      value = value.substring(1);
    }
    if (value.startsWith("L") && value.endsWith(";")) {
      value = value.substring(1, value.length - 1);
    }
    return value;
  };

  Java.enumerateLoadedClasses({
    onMatch(name) {
      const normalized = normalize(name);
      if (!normalized || seen[normalized]) {
        return;
      }
      const lowered = normalized.toLowerCase();
      if (filters.length && filters.indexOf("*") === -1 && !filters.some(function (filter) { return lowered.indexOf(filter) !== -1; })) {
        return;
      }
      seen[normalized] = true;
      classes.push(normalized);
    },
    onComplete() {
      classes.sort();
      console.log("[STATUS] Census reflects the current attached process. Use frida-ps or List Processes for device-wide scope.");
      console.log("[CLASS] total=" + classes.length);
      classes.forEach(function (name) {
        console.log("[CLASS] " + name);
      });
      console.log("[STATUS] class census complete");
    }
  });
});
