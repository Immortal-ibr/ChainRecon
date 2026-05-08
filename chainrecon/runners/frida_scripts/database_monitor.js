Java.perform(function () {
  const config = typeof CHAINRECON_CONFIG !== "undefined" ? CHAINRECON_CONFIG : {};
  const queryFilter = String(config.query_filter || "").toLowerCase();

  const shouldLog = function (sql) {
    const normalized = String(sql || "").toLowerCase();
    return !queryFilter || queryFilter === "*" || normalized.indexOf(queryFilter) !== -1;
  };

  try {
    const SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    const rawQuery = SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;");
    rawQuery.implementation = function (sql, args) {
      if (shouldLog(sql)) {
        console.log("[DB-QUERY] " + sql);
      }
      return rawQuery.call(this, sql, args);
    };

    try {
      const execSQL = SQLiteDatabase.execSQL.overload("java.lang.String");
      execSQL.implementation = function (sql) {
        if (shouldLog(sql)) {
          console.log("[DB-EXEC] " + sql);
        }
        return execSQL.call(this, sql);
      };
    } catch (e) {}

    const insert = SQLiteDatabase.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues");
    insert.implementation = function (table, nullColumnHack, values) {
      const summary = table + " values=" + values;
      if (shouldLog(summary)) {
        console.log("[DB-INSERT] " + summary);
      }
      return insert.call(this, table, nullColumnHack, values);
    };

    const update = SQLiteDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;");
    update.implementation = function (table, values, where, whereArgs) {
      const summary = table + " where=" + where + " values=" + values;
      if (shouldLog(summary)) {
        console.log("[DB-UPDATE] " + summary);
      }
      return update.call(this, table, values, where, whereArgs);
    };
    console.log("[HOOK] android.database.sqlite.SQLiteDatabase");
  } catch (e) {
    console.log("[WARN] SQLiteDatabase hook unavailable: " + e);
  }

  console.log("[STATUS] database monitor ready");
});
