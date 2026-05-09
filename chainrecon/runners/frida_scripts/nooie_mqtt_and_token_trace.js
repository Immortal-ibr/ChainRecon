Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const classFilter = (config.class_filter || "mqtt").toLowerCase();

  const describeValue = function (value) {
    try {
      if (value === null || value === undefined) return "null";
      return value.toString();
    } catch (e) {
      return "<?>";
    }
  };

  const hookMethod = function (className, methodName, tag) {
    try {
      const clazz = Java.use(className);
      if (!clazz[methodName]) return false;
      clazz[methodName].overloads.forEach(function (ov) {
        ov.implementation = function () {
          const args = [];
          for (let i = 0; i < arguments.length; i++) {
            args.push(describeValue(arguments[i]));
          }
          console.log("[" + tag + "] " + className + "." + methodName + "(" + args.join(", ") + ")");
          return ov.apply(this, arguments);
        };
      });
      console.log("[HOOK] " + className + "." + methodName);
      return true;
    } catch (e) {
      return false;
    }
  };

  const hookInterestingMethods = function (className) {
    let clazz;
    try {
      clazz = Java.use(className);
    } catch (e) {
      return 0;
    }
    const interesting = /connect|disconnect|publish|subscribe|token|username|password|clientid|broker|serveruri/i;
    const seen = {};
    let count = 0;
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
            console.log("[MQTT-CALL] " + className + "." + methodName + "(" + args.join(", ") + ")");
            const result = ov.apply(this, arguments);
            console.log("[MQTT-RET] " + className + "." + methodName + " => " + describeValue(result));
            return result;
          };
          count += 1;
        });
      }
    } catch (e) {}
    if (count > 0) {
      console.log("[HOOK] " + className + " interesting MQTT overloads=" + count);
    }
    return count;
  };

  const extraClasses = Array.isArray(config.additional_classes) ? config.additional_classes : [];
  const candidates = [
    ["com.thingclips.smart.mqtt.MqttAndroidClient", "getMqttToken", "MQTT-TOKEN"],
    ["com.thingclips.smart.mqtt.MqttAndroidClient", "connect", "MQTT-CONNECT"],
    ["org.eclipse.paho.android.service.MqttAndroidClient", "publish", "MQTT-PUBLISH"],
    ["org.eclipse.paho.android.service.MqttAndroidClient", "subscribe", "MQTT-SUBSCRIBE"],
  ];
  let hooked = 0;
  candidates.forEach(function (candidate) {
    if (candidate[0].toLowerCase().indexOf(classFilter) !== -1 || classFilter === "mqtt") {
      if (hookMethod(candidate[0], candidate[1], candidate[2])) {
        hooked += 1;
      }
    }
  });

  const loaded = [];
  Java.enumerateLoadedClasses({
    onMatch(name) {
      const normalized = name.toLowerCase();
      if (
        (normalized.indexOf("mqtt") !== -1 || normalized.indexOf(classFilter) !== -1) &&
        normalized.indexOf("$") === -1
      ) {
        loaded.push(name);
      }
    },
    onComplete() {
  loaded.slice(0, 40).forEach(function (name) {
        hooked += hookInterestingMethods(name);
      });
      extraClasses.forEach(function (name) {
        hooked += hookInterestingMethods(name);
      });
      console.log("[STATUS] nooie mqtt trace ready hooks=" + hooked + " scanned_classes=" + loaded.length);
    }
  });
});
