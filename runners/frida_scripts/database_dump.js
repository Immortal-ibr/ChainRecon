/*
 * database_dump.js — Monitor and dump SQLite database operations
 *
 * Hooks SQLiteDatabase to log queries, inserts, updates, and raw SQL.
 * Useful for finding locally stored credentials, tokens, and PII.
 */

Java.perform(function () {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

    // --- rawQuery ----------------------------------------------------------
    SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (sql, args) {
        console.log("[SQLite rawQuery] " + sql);
        if (args !== null) {
            for (var i = 0; i < args.length; i++) {
                console.log("  arg[" + i + "] = " + args[i]);
            }
        }
        return this.rawQuery(sql, args);
    };

    // --- query (7-arg form) -----------------------------------------------
    try {
        SQLiteDatabase.query.overload(
            "java.lang.String", "[Ljava.lang.String;",
            "java.lang.String", "[Ljava.lang.String;",
            "java.lang.String", "java.lang.String", "java.lang.String"
        ).implementation = function (table, cols, sel, selArgs, group, having, order) {
            console.log("[SQLite query] table=" + table + " selection=" + sel);
            return this.query(table, cols, sel, selArgs, group, having, order);
        };
    } catch (e) {}

    // --- insert ------------------------------------------------------------
    SQLiteDatabase.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function (table, nullColHack, values) {
        console.log("[SQLite insert] table=" + table + " values=" + values);
        return this.insert(table, nullColHack, values);
    };

    // --- update ------------------------------------------------------------
    SQLiteDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function (table, values, where, whereArgs) {
        console.log("[SQLite update] table=" + table + " where=" + where + " values=" + values);
        return this.update(table, values, where, whereArgs);
    };

    // --- delete ------------------------------------------------------------
    SQLiteDatabase.delete.overload("java.lang.String", "java.lang.String", "[Ljava.lang.String;").implementation = function (table, where, whereArgs) {
        console.log("[SQLite delete] table=" + table + " where=" + where);
        return this.delete(table, where, whereArgs);
    };

    // --- execSQL -----------------------------------------------------------
    try {
        SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
            console.log("[SQLite execSQL] " + sql);
            return this.execSQL(sql);
        };
    } catch (e) {}

    // --- openDatabase ------------------------------------------------------
    try {
        SQLiteDatabase.openDatabase.overload(
            "java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory", "int"
        ).implementation = function (path, factory, flags) {
            console.log("[SQLite openDatabase] " + path);
            return this.openDatabase(path, factory, flags);
        };
    } catch (e) {}

    console.log("[*] SQLite database hooks installed");
});
