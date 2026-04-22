Java.perform(() => {
  const classes = [];
  const seen = {};

  Java.enumerateLoadedClasses({
    onMatch(name) {
      if (name.startsWith('com.nooie.home')) {
        classes.push(name);
      }
    },
    onComplete() {
      console.log('[*] Matching loaded classes: ' + classes.length);

      classes.forEach(name => {
        try {
          Java.choose(name, {
            onMatch(instance) {
              const key = name + ' @ ' + instance.$h;
              if (!seen[key]) {
                seen[key] = true;
                console.log('[INSTANCE] ' + name + ' -> ' + instance);
              }
            },
            onComplete() {}
          });
        } catch (e) {
          // Ignore classes that can't be instantiated / scanned cleanly
          // e.g. interfaces, abstract classes, weird runtime types
        }
      });

      console.log('[*] Scan complete');
    }
  });
});