/**
 * Enumerate all loaded Java classes matching a user-supplied filter.
 * If no filter is set, lists everything (can be huge).
 *
 * Usage:  frida -U -n <app> -l list_classes.js
 *  Then:  send({ filter: "com.example" })   // optional, via RPC
 *
 * The script also looks for live heap instances of each match.
 */
Java.perform(() => {
  const filter = typeof FILTER !== "undefined" ? FILTER : "";
  const classes = [];
  const seen = {};

  Java.enumerateLoadedClasses({
    onMatch(name) {
      if (filter === "" || name.indexOf(filter) !== -1) {
        classes.push(name);
      }
    },
    onComplete() {
      console.log("[*] Matching loaded classes: " + classes.length);
      classes.sort();

      classes.forEach(name => {
        console.log("  " + name);
        try {
          Java.choose(name, {
            onMatch(instance) {
              const key = name + " @ " + instance.$h;
              if (!seen[key]) {
                seen[key] = true;
                console.log("    [INSTANCE] " + instance);
              }
            },
            onComplete() {}
          });
        } catch (e) {
          // Some classes can't be scanned
        }
      });

      console.log("[*] Class enumeration complete");
    }
  });
});
