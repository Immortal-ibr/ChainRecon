Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const className = config.class_name || "";
  const methodName = config.method_name || "";

  if (!className || !methodName) {
    console.log("[ERROR] class_name and method_name are required.");
    return;
  }

  let clazz;
  try {
    clazz = Java.use(className);
  } catch (e) {
    console.log("[ERROR] class_not_found " + className);
    return;
  }

  if (!clazz[methodName]) {
    console.log("[ERROR] method_not_found " + className + "." + methodName);
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

  clazz[methodName].overloads.forEach(function (ov, index) {
    console.log("[HOOK] " + className + "." + methodName + " overload=" + index);
    ov.implementation = function () {
      const args = [];
      for (let argIndex = 0; argIndex < arguments.length; argIndex++) {
        args.push(describeValue(arguments[argIndex]));
      }
      console.log("[CALL] " + className + "." + methodName + "(" + args.join(", ") + ")");
      const result = ov.apply(this, arguments);
      console.log("[RET] " + className + "." + methodName + " => " + describeValue(result));
      return result;
    };
  });

  console.log("[STATUS] hook_method ready");
});
