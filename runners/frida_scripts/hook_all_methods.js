const TARGET_CLASSES = [];
/**
 * Hook every method of one or more classes and log calls with arguments.
 *
 * Set TARGET_CLASSES before loading, e.g.:
 *   const TARGET_CLASSES = ["com.example.MyClass"];
 *
 * Usage:  frida -U -n <app> -l hook_all_methods.js
 */
Java.perform(function () {
  const targets = typeof TARGET_CLASSES !== "undefined"
    ? TARGET_CLASSES
    : [];

  if (targets.length === 0) {
    console.log("[!] No TARGET_CLASSES defined. Set them at the top of the script.");
    return;
  }

  for (let c = 0; c < targets.length; c++) {
    const className = targets[c];
    let clazz;
    try {
      clazz = Java.use(className);
    } catch (e) {
      console.log("[!] Class not found: " + className);
      continue;
    }

    const methods = clazz.class.getDeclaredMethods();
    const seen = new Set();

    for (let i = 0; i < methods.length; i++) {
      const name = methods[i].getName();
      if (seen.has(name) || !clazz[name]) continue;
      seen.add(name);

      const overloads = clazz[name].overloads;
      for (let j = 0; j < overloads.length; j++) {
        const ov = overloads[j];
        const methodName = name;
        console.log("[*] Hooking " + className + "." + methodName);

        ov.implementation = function () {
          const args = [];
          for (let a = 0; a < arguments.length; a++) {
            try {
              args.push(arguments[a] !== null ? arguments[a].toString() : "null");
            } catch (e) {
              args.push("<?>");
            }
          }
          console.log("[+] " + className + "." + methodName + "(" + args.join(", ") + ")");
          return ov.apply(this, arguments);
        };
      }
    }
    console.log("[*] Hooked all methods of " + className);
  }
});
