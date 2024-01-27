// See the file "COPYING" in the main distribution directory for copyright.

#include "SQLite.h"

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/Func.h"
#include "zeek/Val.h"

namespace zeek::storage::backends::sqlite {

storage::Backend* SQLite::Instantiate() { return new SQLite(); }

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
ErrorResult SQLite::DoOpen(RecordValPtr config) {
    if ( sqlite3_threadsafe() == 0 ) {
        std::string res =
            "SQLite reports that it is not threadsafe. Zeek needs a threadsafe version of "
            "SQLite. Aborting";
        Error(res.c_str());
        return res;
    }

    // Allow connections to same DB to use single data/schema cache. Also
    // allows simultaneous writes to one file.
#ifndef ZEEK_TSAN
    sqlite3_enable_shared_cache(1);
#endif

    StringValPtr path = config->GetField<StringVal>("database_path");
    full_path = zeek::filesystem::path(path->ToStdString());
    table_name = config->GetField<StringVal>("table_name")->ToStdString();

    if ( checkError(sqlite3_open_v2(full_path.c_str(), &db,
                                    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL)) ) {
        db = nullptr;
        return "Failed to open database connection";
    }

    std::string create = "create table if not exists " + table_name + " (";
    create.append("key_str text primary key, value_str text not null);");

    char* errorMsg = nullptr;
    int res = sqlite3_exec(db, create.c_str(), NULL, NULL, &errorMsg);
    if ( res != SQLITE_OK ) {
        Error(util::fmt("Error executing table creation statement: %s", errorMsg));
        sqlite3_free(errorMsg);
        sqlite3_close(db);
        db = nullptr;
        return "Failed to initialize database table";
    }

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void SQLite::Done() {
    if ( db ) {
        if ( int res = sqlite3_close_v2(db); res != SQLITE_OK )
            Error("Sqlite could not close connection");

        db = nullptr;
    }
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult SQLite::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    if ( ! db )
        return "Database was not open";

    auto json_key = key->ToJSON();
    auto json_value = value->ToJSON();

    std::string stmt = "INSERT INTO ";
    stmt.append(table_name);
    stmt.append("(key_str, value_str) VALUES('");
    stmt.append(json_key->ToStdStringView());
    stmt.append("', '");
    stmt.append(json_value->ToStdStringView());
    if ( ! overwrite )
        stmt.append("');");
    else {
        // if overwriting, add an UPSERT conflict resolution block
        stmt.append("') ON CONFLICT(key_str) DO UPDATE SET value_str='");
        stmt.append(json_value->ToStdStringView());
        stmt.append("';");
    }

    char* errorMsg = nullptr;
    int res = sqlite3_exec(db, stmt.c_str(), NULL, NULL, &errorMsg);
    if ( res != SQLITE_OK ) {
        return errorMsg;
    }

    return std::nullopt;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult SQLite::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( ! db )
        return nonstd::unexpected<std::string>("Database was not open");

    auto json_key = key->ToJSON();

    std::string stmt = "SELECT value_str from " + table_name + " where key_str = '";
    stmt.append(json_key->ToStdStringView());
    stmt.append("';");

    char* errorMsg = nullptr;
    sqlite3_stmt* st;
    if ( checkError(sqlite3_prepare_v2(db, stmt.c_str(), static_cast<int>(stmt.size() + 1), &st, NULL)) )
        return nonstd::unexpected<std::string>("Failed to prepare select statement");

    int errorcode = sqlite3_step(st);
    if ( errorcode == SQLITE_ROW ) {
        // Column 1 is the value
        const char* text = (const char*)sqlite3_column_text(st, 0);
        auto val = zeek::detail::ValFromJSON(text, val_type, Func::nil);
        if ( std::holds_alternative<ValPtr>(val) ) {
            ValPtr val_v = std::get<ValPtr>(val);
            return val_v;
        }
        else {
            return nonstd::unexpected<std::string>(std::get<std::string>(val));
        }
    }

    // TODO: return status from the sqlite call
    return nonstd::unexpected<std::string>("Failed to find row for key");
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult SQLite::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( ! db )
        return "Database was not open";

    auto json_key = key->ToJSON();

    std::string stmt = "DELETE from " + table_name + " where key_str = \'";
    stmt.append(json_key->ToStdStringView());
    stmt.append("\'");

    char* errorMsg = nullptr;
    int res = sqlite3_exec(db, stmt.c_str(), NULL, NULL, &errorMsg);
    if ( res != SQLITE_OK ) {
        return errorMsg;
    }

    return std::nullopt;
}

// returns true in case of error
bool SQLite::checkError(int code) {
    if ( code != SQLITE_OK && code != SQLITE_DONE ) {
        Error(util::fmt("SQLite call failed: %s", sqlite3_errmsg(db)));
        return true;
    }

    return false;
}

} // namespace zeek::storage::backends::sqlite
