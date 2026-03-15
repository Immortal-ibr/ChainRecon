Java.perform(function () {
    const classes = ["com.yrcx.webrtc.controller.PlayEvent"];
    for (let c = 0; c < classes.length; c++) {
        const className = classes[c];
        const clazz = Java.use(className);
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
                console.log("Hooking function " + className + "." + methodName);
                ov.implementation = function () {
                    let args = [];
                    for (let i = 0; i < arguments.length; i++) {
                        try {
                            args.push(arguments[i].toString());
                        } catch (e) {
                            args.push("<?>");
                        }
                    }
                    console.log("[+] " + className + "." + methodName + "(" + args.join(", ") + ")");
                    return ov.apply(this, arguments);
                };
            }
        }
    }
});