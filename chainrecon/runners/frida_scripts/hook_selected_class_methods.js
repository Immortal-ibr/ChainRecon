Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const targets = Array.isArray(config.class_names) ? config.class_names : [];
  const maxEventsPerSecond = parseInt(config.max_events_per_second || "50", 10);
  let windowStart = Date.now();
  let emittedInWindow = 0;
  let droppedInWindow = 0;

  const emit = function (line) {
    const now = Date.now();
    if (now - windowStart >= 1000) {
      if (droppedInWindow > 0) {
        console.log("[DROPPED] hook_all_methods dropped_event_count=" + droppedInWindow);
      }
      windowStart = now;
      emittedInWindow = 0;
      droppedInWindow = 0;
    }
    if (emittedInWindow >= maxEventsPerSecond) {
      droppedInWindow += 1;
      return;
    }
    emittedInWindow += 1;
    console.log(line);
  };

  if (!targets.length) {
    emit("[ERROR] No class_names were provided.");
    return;
  }

  const describeValue = function (value) {
    try {
      if (value === null || value === undefined) return "null";
      return value.toString();
    } catch (e) {
      return "<?>";
    }
  };

  targets.forEach(function (className) {
    let clazz;
    try {
      clazz = Java.use(className);
    } catch (e) {
      emit("[ERROR] class_not_found " + className);
      return;
    }

    const methods = clazz.class.getDeclaredMethods();
    const seen = {};

    for (let i = 0; i < methods.length; i++) {
      const methodName = methods[i].getName();
      if (seen[methodName] || !clazz[methodName]) continue;
      seen[methodName] = true;

      clazz[methodName].overloads.forEach(function (ov, index) {
        emit("[HOOK] " + className + "." + methodName + " overload=" + index);
        ov.implementation = function () {
          const args = [];
          for (let argIndex = 0; argIndex < arguments.length; argIndex++) {
            args.push(describeValue(arguments[argIndex]));
          }
          emit("[CALL] " + className + "." + methodName + "(" + args.join(", ") + ")");
          const result = ov.apply(this, arguments);
          emit("[RET] " + className + "." + methodName + " => " + describeValue(result));
          return result;
        };
      });
    }
  });

  emit("[STATUS] hook_all_methods ready");
});
