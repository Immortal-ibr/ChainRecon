Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const filter = (config.class_filter || "").toLowerCase();

  const describeValue = function (value) {
    try {
      if (value === null || value === undefined) return "null";
      return value.toString();
    } catch (e) {
      return "<?>";
    }
  };

  const hookLifecycleMethods = function (className) {
    let clazz;
    try {
      clazz = Java.use(className);
    } catch (e) {
      return 0;
    }
    const interesting = /start|stop|connect|disconnect|play|pause|resume|decode|render|frame|stream|ice|sdp|offer|answer/i;
    const seen = {};
    let hooks = 0;
    try {
      const methods = clazz.class.getDeclaredMethods();
      for (let i = 0; i < methods.length; i++) {
        const methodName = methods[i].getName();
        if (seen[methodName] || !interesting.test(methodName) || !clazz[methodName]) continue;
        seen[methodName] = true;
        clazz[methodName].overloads.forEach(function (ov) {
          ov.implementation = function () {
            const args = [];
            for (let j = 0; j < arguments.length; j++) {
              args.push(describeValue(arguments[j]));
            }
            console.log("[STREAM-CALL] " + className + "." + methodName + "(" + args.join(", ") + ")");
            const result = ov.apply(this, arguments);
            console.log("[STREAM-RET] " + className + "." + methodName + " => " + describeValue(result));
            return result;
          };
          hooks += 1;
        });
      }
    } catch (e) {}
    if (hooks > 0) {
      console.log("[HOOK] " + className + " stream overloads=" + hooks);
    }
    return hooks;
  };

  const candidates = [];
  Java.enumerateLoadedClasses({
    onMatch(name) {
      const normalized = name.toLowerCase();
      const looksInteresting =
        normalized.indexOf("webrtc") !== -1 ||
        normalized.indexOf("stream") !== -1 ||
        normalized.indexOf("player") !== -1 ||
        normalized.indexOf("camera") !== -1;
      if (looksInteresting && (!filter || normalized.indexOf(filter) !== -1)) {
        candidates.push(name);
      }
    },
    onComplete() {
      candidates.sort();
      console.log("[STREAM] loaded_classes=" + candidates.length);
      candidates.slice(0, 80).forEach(function (name) {
        console.log("[STREAM-CLASS] " + name);
      });
      let hooks = 0;
      candidates.slice(0, 40).forEach(function (name) {
        hooks += hookLifecycleMethods(name);
      });
      console.log("[STATUS] nooie stream trace ready hooks=" + hooks);
    }
  });
});
