Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const filters = (Array.isArray(config.class_filter) ? config.class_filter : [config.class_filter || ""])
    .map(function (value) { return String(value || "").trim().toLowerCase(); })
    .filter(function (value) { return value.length > 0; });
  const classes = [];
  const seen = {};

  const canonicalizeName = function (name) {
    let normalized = String(name || "");
    while (normalized.startsWith("[")) {
      normalized = normalized.substring(1);
    }
    if (normalized.startsWith("L") && normalized.endsWith(";")) {
      normalized = normalized.substring(1, normalized.length - 1);
    }
    return normalized;
  };

  Java.enumerateLoadedClasses({
    onMatch(name) {
      const canonical = canonicalizeName(name);
      if (!canonical || seen[canonical]) {
        return;
      }
      const lower = canonical.toLowerCase();
      if (!filters.length || filters.some(function (filter) { return lower.indexOf(filter) !== -1; })) {
        seen[canonical] = true;
        classes.push(canonical);
      }
    },
    onComplete() {
      classes.sort();
      console.log("[STATUS] App-process class listing only; use List Processes for device-wide discovery.");
      console.log("[CLASS] total=" + classes.length + " filters=" + (filters.length ? filters.join(",") : "*"));
      classes.forEach(function (name) {
        console.log("[CLASS] " + name);
      });
      console.log("[STATUS] class enumeration complete");
    }
  });
});
