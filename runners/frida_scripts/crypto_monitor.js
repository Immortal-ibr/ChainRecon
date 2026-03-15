/**
 * Monitor cryptographic operations in the app.
 *
 * Hooks:
 *  - javax.crypto.Cipher.doFinal (encryption/decryption payloads)
 *  - javax.crypto.Cipher.init    (algorithm + key)
 *  - java.security.MessageDigest.digest (hashing)
 *  - javax.crypto.Mac.doFinal    (HMAC)
 *
 * Useful for IoT apps that encrypt MQTT payloads, API tokens, etc.
 *
 * Usage:  frida -U -n <app> -l crypto_monitor.js
 */
Java.perform(function () {
  console.log("[*] Crypto Monitor loaded");

  function bytesToHex(bytes) {
    if (!bytes) return "(null)";
    const arr = Java.array("byte", bytes);
    let hex = "";
    for (let i = 0; i < arr.length && i < 64; i++) {
      hex += ("0" + (arr[i] & 0xff).toString(16)).slice(-2);
    }
    if (arr.length > 64) hex += "...(" + arr.length + " bytes)";
    return hex;
  }

  // 1. Cipher.init — log algorithm and mode
  try {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
      const modeStr = mode === 1 ? "ENCRYPT" : mode === 2 ? "DECRYPT" : "mode=" + mode;
      console.log("[CRYPTO] Cipher.init " + modeStr + " alg=" + this.getAlgorithm());
      console.log("         Key: " + bytesToHex(key.getEncoded()));
      return this.init(mode, key);
    };
    console.log("[+] Hooked Cipher.init");
  } catch (e) {
    console.log("[-] Cipher.init hook failed: " + e);
  }

  // 2. Cipher.doFinal — log plaintext/ciphertext
  try {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
      console.log("[CRYPTO] Cipher.doFinal input:  " + bytesToHex(input));
      const result = this.doFinal(input);
      console.log("[CRYPTO] Cipher.doFinal output: " + bytesToHex(result));
      return result;
    };
    console.log("[+] Hooked Cipher.doFinal");
  } catch (e) {
    console.log("[-] Cipher.doFinal hook failed: " + e);
  }

  // 3. MessageDigest.digest — log hash input
  try {
    const MD = Java.use("java.security.MessageDigest");
    MD.digest.overload("[B").implementation = function (input) {
      console.log("[HASH]   " + this.getAlgorithm() + " input: " + bytesToHex(input));
      const result = this.digest(input);
      console.log("[HASH]   " + this.getAlgorithm() + " output: " + bytesToHex(result));
      return result;
    };
    console.log("[+] Hooked MessageDigest.digest");
  } catch (e) {
    console.log("[-] MessageDigest hook failed: " + e);
  }

  // 4. Mac.doFinal — log HMAC
  try {
    const Mac = Java.use("javax.crypto.Mac");
    Mac.doFinal.overload("[B").implementation = function (input) {
      console.log("[HMAC]   " + this.getAlgorithm() + " input: " + bytesToHex(input));
      const result = this.doFinal(input);
      console.log("[HMAC]   " + this.getAlgorithm() + " output: " + bytesToHex(result));
      return result;
    };
    console.log("[+] Hooked Mac.doFinal");
  } catch (e) {
    console.log("[-] Mac hook failed: " + e);
  }

  console.log("[*] Crypto Monitor ready");
});
