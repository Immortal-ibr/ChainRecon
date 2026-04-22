function dumpBuffer(buf, maxLen) {
  const BufferCls = Java.use("java.nio.Buffer");
  const ByteBufferCls = Java.use("java.nio.ByteBuffer");

  const b = Java.cast(buf, BufferCls);
  const bb = Java.cast(buf, ByteBufferCls);

  const lim = b.limit.overload().call(b);
  const n = Math.min(lim, maxLen || 64);

  let hex = "";
  let ascii = "";

  for (let i = 0; i < n; i++) {
    let x = bb.get.overload('int').call(bb, i);
    if (x < 0) x += 256;

    hex += ("0" + x.toString(16)).slice(-2) + " ";
    ascii += (x >= 32 && x <= 126) ? String.fromCharCode(x) : ".";
  }

  console.log("[hex]   " + hex);
  console.log("[ascii] " + ascii);
}

Java.perform(function () {
    const classes = ["org.webrtc.AndroidVideoDecoder"]; 
    for (let c = 0; c < classes.length; c++) {
        const className = classes[c];
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
                const functionName = name;
                console.log("Hooking class: " + className + " Function: " + functionName);
                ov.implementation = function () {
                    let args = [];
                    for (let i = 0; i < arguments.length; i++) {
                        try {
                            args.push(arguments[i].toString());
                        } catch (e) {
                            args.push("<?>");
                        }
                    }
                    if (functionName == "decode") {
                        const EncodedImage = Java.use("org.webrtc.EncodedImage");
                        console.log("[+] Classname: " + className + " Function: " + functionName + "(" + args.join(", ") + ")");
                        const img = Java.cast(arguments[0], EncodedImage);
                        const buf = img.getBuffer();
                        console.log("buffer: " + buf);
                        dumpBuffer(buf, 128);
                    }
                    return ov.apply(this, arguments);
                };
            }
        }
    }
});
