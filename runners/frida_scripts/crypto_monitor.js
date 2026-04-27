Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const algorithmFilter = String(config.algorithm_filter || "").toLowerCase();
  const maxBytes = Math.max(parseInt(config.max_bytes || "64", 10) || 64, 8);

  const shouldLogAlgorithm = function (algorithm) {
    const normalized = String(algorithm || "").toLowerCase();
    return !algorithmFilter || algorithmFilter === "*" || normalized.indexOf(algorithmFilter) !== -1;
  };

  const bytesToHex = function (bytes) {
    if (!bytes) return "(null)";
    const arr = Java.array("byte", bytes);
    let hex = "";
    for (let i = 0; i < arr.length && i < maxBytes; i++) {
      hex += ("0" + (arr[i] & 0xff).toString(16)).slice(-2);
    }
    if (arr.length > maxBytes) {
      hex += "...(" + arr.length + " bytes)";
    }
    return hex;
  };

  try {
    const Cipher = Java.use("javax.crypto.Cipher");
    const cipherInit = Cipher.init.overload("int", "java.security.Key");
    cipherInit.implementation = function (mode, key) {
      const algorithm = this.getAlgorithm();
      if (!shouldLogAlgorithm(algorithm)) {
        return cipherInit.call(this, mode, key);
      }
      const modeText = mode === 1 ? "ENCRYPT" : mode === 2 ? "DECRYPT" : "mode=" + mode;
      console.log("[CRYPTO-INIT] " + modeText + " alg=" + algorithm);
      try {
        console.log("[CRYPTO-KEY] " + bytesToHex(key.getEncoded()));
      } catch (e) {
        console.log("[CRYPTO-KEY] <not exportable>");
      }
      return cipherInit.call(this, mode, key);
    };
    console.log("[HOOK] javax.crypto.Cipher.init");
  } catch (e) {
    console.log("[WARN] Cipher.init hook failed: " + e);
  }

  try {
    const Cipher = Java.use("javax.crypto.Cipher");
    const doFinalBytes = Cipher.doFinal.overload("[B");
    doFinalBytes.implementation = function (input) {
      const algorithm = this.getAlgorithm();
      if (!shouldLogAlgorithm(algorithm)) {
        return doFinalBytes.call(this, input);
      }
      console.log("[CRYPTO-IN] " + algorithm + " " + bytesToHex(input));
      const result = doFinalBytes.call(this, input);
      console.log("[CRYPTO-OUT] " + algorithm + " " + bytesToHex(result));
      return result;
    };
    console.log("[HOOK] javax.crypto.Cipher.doFinal");
  } catch (e) {
    console.log("[WARN] Cipher.doFinal hook failed: " + e);
  }

  try {
    const MessageDigest = Java.use("java.security.MessageDigest");
    const digestBytes = MessageDigest.digest.overload("[B");
    digestBytes.implementation = function (input) {
      const algorithm = this.getAlgorithm();
      if (!shouldLogAlgorithm(algorithm)) {
        return digestBytes.call(this, input);
      }
      console.log("[HASH-IN] " + algorithm + " " + bytesToHex(input));
      const result = digestBytes.call(this, input);
      console.log("[HASH-OUT] " + algorithm + " " + bytesToHex(result));
      return result;
    };
    console.log("[HOOK] java.security.MessageDigest.digest");
  } catch (e) {
    console.log("[WARN] MessageDigest.digest hook failed: " + e);
  }

  try {
    const Mac = Java.use("javax.crypto.Mac");
    const macDoFinalBytes = Mac.doFinal.overload("[B");
    macDoFinalBytes.implementation = function (input) {
      const algorithm = this.getAlgorithm();
      if (!shouldLogAlgorithm(algorithm)) {
        return macDoFinalBytes.call(this, input);
      }
      console.log("[HMAC-IN] " + algorithm + " " + bytesToHex(input));
      const result = macDoFinalBytes.call(this, input);
      console.log("[HMAC-OUT] " + algorithm + " " + bytesToHex(result));
      return result;
    };
    console.log("[HOOK] javax.crypto.Mac.doFinal");
  } catch (e) {
    console.log("[WARN] Mac.doFinal hook failed: " + e);
  }

  console.log("[STATUS] crypto monitor ready");
});
