Java.perform(function () {
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