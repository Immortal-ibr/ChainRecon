/**
 * Hook a single method and log every call with arguments + return value.
 *
 * Set TARGET_CLASS and TARGET_METHOD before loading:
 *   const TARGET_CLASS  = "com.example.MyClass";
 *   const TARGET_METHOD = "myMethod";
 *
 * Usage:  frida -U -n <app> -l hook_method.js
 */
Java.perform(function () {
  const cls  = typeof TARGET_CLASS  !== "undefined" ? TARGET_CLASS  : "";
  const meth = typeof TARGET_METHOD !== "undefined" ? TARGET_METHOD : "";

  if (!cls || !meth) {
    console.log("[!] Set TARGET_CLASS and TARGET_METHOD at the top of the script.");
    return;
  }

  let clazz;
  try {
    clazz = Java.use(cls);
  } catch (e) {
    console.log("[!] Class not found: " + cls);
    return;
  }

  if (!clazz[meth]) {
    console.log("[!] Method not found: " + cls + "." + meth);
    return;
  }

  const overloads = clazz[meth].overloads;
  console.log("[*] Hooking " + cls + "." + meth + " (" + overloads.length + " overload(s))");

  for (let i = 0; i < overloads.length; i++) {
    const ov = overloads[i];
    ov.implementation = function () {
      const args = [];
      for (let a = 0; a < arguments.length; a++) {
        try {
          args.push(arguments[a] !== null ? arguments[a].toString() : "null");
        } catch (e) {
          args.push("<?>");
        }
      }
      console.log("[CALL]   " + cls + "." + meth + "(" + args.join(", ") + ")");
      const ret = ov.apply(this, arguments);
      try {
        console.log("[RETURN] " + (ret !== null ? ret.toString() : "null"));
      } catch (e) {
        console.log("[RETURN] <?>");
      }
      return ret;
    };
  }
});
