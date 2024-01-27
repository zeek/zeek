// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/sqlite/SQLite.h"

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/Func.h"
#include "zeek/Val.h"

namespace zeek::storage::backend::sqlite {

storage::BackendPtr SQLite::Instantiate(std::string_view tag) { return make_intrusive<SQLite>(tag); }

/**
 * Called by the manager system to open the backend.
 */
ErrorResult SQLite::DoOpen(RecordValPtr options) {
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

    StringValPtr path = options->GetField<StringVal>("database_path");
    full_path = zeek::filesystem::path(path->ToStdString()).string();
    table_name = options->GetField<StringVal>("table_name")->ToStdString();

    auto open_res =
        checkError(sqlite3_open_v2(full_path.c_str(), &db,
                                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL));
    if ( open_res.has_value() ) {
        sqlite3_close_v2(db);
        db = nullptr;
        return open_res;
    }

    std::string create = "create table if not exists " + table_name + " (";
    create.append("key_str text primary key, value_str text not null);");

    char* errorMsg = nullptr;
    int res = sqlite3_exec(db, create.c_str(), NULL, NULL, &errorMsg);
    if ( res != SQLITE_OK ) {
        std::string err = util::fmt("Error executing table creation statement: %s", errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        sqlite3_close(db);
        db = nullptr;
        return err;
    }

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void SQLite::Close() {
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
        return zeek::unexpected<std::string>("Database was not open");

    auto json_key = key->ToJSON();

    std::string stmt = "SELECT value_str from " + table_name + " where key_str = '";
    stmt.append(json_key->ToStdStringView());
    stmt.append("';");

    char* errorMsg = nullptr;
    sqlite3_stmt* st;
    auto res = checkError(sqlite3_prepare_v2(db, stmt.c_str(), static_cast<int>(stmt.size() + 1), &st, NULL));
    if ( res.has_value() )
        return zeek::unexpected<std::string>(util::fmt("Failed to prepare select statement: %s", res.value().c_str()));

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
            return zeek::unexpected<std::string>(std::get<std::string>(val));
        }
    }

    return zeek::unexpected<std::string>(util::fmt("Failed to find row for key: %s", sqlite3_errstr(errorcode)));
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
ErrorResult SQLite::checkError(int code) {
    if ( code != SQLITE_OK && code != SQLITE_DONE ) {
        std::string msg = util::fmt("SQLite call failed: %s", sqlite3_errmsg(db));
        Error(msg.c_str());
        return msg;
    }

    return std::nullopt;
}

} // namespace zeek::storage::backend::sqlite
