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

    auto open_res = checkError(sqlite3_open_v2(full_path.c_str(), &db,
                                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL));
    if ( open_res.has_value() ) {
        db = nullptr;
        return open_res;
    }

    std::string create = "create table if not exists " + table_name + " (";
    create.append("key_str text primary key, value_str text not null, expire_time real);");

    char* errorMsg = nullptr;
    if ( int res = sqlite3_exec(db, create.c_str(), NULL, NULL, &errorMsg); res != SQLITE_OK ) {
        std::string err = util::fmt("Error executing table creation statement: %s", errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        Done();
        return err;
    }

    if ( int res = sqlite3_exec(db, "pragma integrity_check", NULL, NULL, &errorMsg); res != SQLITE_OK ) {
        std::string err = util::fmt("Error executing integrity check: %s", errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        Done();
        return err;
    }

    auto tuning_params = config->GetField<TableVal>("tuning_params")->ToMap();
    for ( const auto& [k, v] : tuning_params ) {
        auto ks = k->AsListVal()->Idx(0)->AsStringVal();
        auto vs = v->AsStringVal();
        std::string cmd = util::fmt("pragma %s = %s", ks->ToStdStringView().data(), vs->ToStdStringView().data());

        if ( int res = sqlite3_exec(db, cmd.c_str(), NULL, NULL, &errorMsg); res != SQLITE_OK ) {
            std::string err = util::fmt("Error executing tuning pragma statement: %s", errorMsg);
            Error(err.c_str());
            sqlite3_free(errorMsg);
            Done();
            return err;
        }
    }

    static std::map<std::string, std::string> statements =
        {{"put", util::fmt("insert into %s (key_str, value_str, expire_time) values(?, ?, ?)", table_name.c_str())},
         {"put_update",
          util::fmt("insert into %s (key_str, value_str, expire_time) values(?, ?, ?) ON CONFLICT(key_str) "
                    "DO UPDATE SET value_str=?",
                    table_name.c_str())},
         {"get", util::fmt("select value_str from %s where key_str=?", table_name.c_str())},
         {"erase", util::fmt("delete from %s where key_str=?", table_name.c_str())},
         {"expire", util::fmt("delete from %s where expire_time > 0 and expire_time <= ?", table_name.c_str())}};

    for ( const auto& [key, stmt] : statements ) {
        sqlite3_stmt* ps;
        if ( auto prep_res = checkError(sqlite3_prepare_v2(db, stmt.c_str(), stmt.size(), &ps, NULL));
             prep_res.has_value() ) {
            Done();
            return prep_res;
        }

        prepared_stmts.insert({key, ps});
    }

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void SQLite::Done() {
    if ( db ) {
        for ( const auto& [k, stmt] : prepared_stmts ) {
            sqlite3_finalize(stmt);
        }

        prepared_stmts.clear();

        char* errmsg;
        if ( int res = sqlite3_exec(db, "pragma optimize", NULL, NULL, &errmsg); res != SQLITE_OK ) {
            Error(util::fmt("Sqlite failed to optimize at shutdown: %s", errmsg));
            sqlite3_free(&errmsg);
        }

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

    sqlite3_stmt* stmt;
    if ( ! overwrite )
        stmt = prepared_stmts["put"];
    else
        stmt = prepared_stmts["put_update"];

    auto key_str = json_key->ToStdStringView();
    if ( auto res = checkError(sqlite3_bind_text(stmt, 1, key_str.data(), key_str.size(), SQLITE_STATIC));
         res.has_value() ) {
        sqlite3_reset(stmt);
        return res;
    }

    auto value_str = json_value->ToStdStringView();
    if ( auto res = checkError(sqlite3_bind_text(stmt, 2, value_str.data(), value_str.size(), SQLITE_STATIC));
         res.has_value() ) {
        sqlite3_reset(stmt);
        return res;
    }

    if ( auto res = checkError(sqlite3_bind_double(stmt, 3, expiration_time)); res.has_value() ) {
        sqlite3_reset(stmt);
        return res;
    }

    if ( overwrite ) {
        if ( auto res = checkError(sqlite3_bind_text(stmt, 4, value_str.data(), value_str.size(), SQLITE_STATIC));
             res.has_value() ) {
            sqlite3_reset(stmt);
            return res;
        }
    }

    if ( auto res = checkError(sqlite3_step(stmt)); res.has_value() ) {
        sqlite3_reset(stmt);
        return res;
    }

    sqlite3_reset(stmt);
    return std::nullopt;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult SQLite::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( ! db )
        return nonstd::unexpected<std::string>("Database was not open");

    auto json_key = key->ToJSON();
    auto stmt = prepared_stmts["get"];

    auto key_str = json_key->ToStdStringView();
    if ( auto res = checkError(sqlite3_bind_text(stmt, 1, key_str.data(), key_str.size(), SQLITE_STATIC));
         res.has_value() ) {
        sqlite3_reset(stmt);
        return nonstd::unexpected<std::string>(res.value());
    }

    int errorcode = sqlite3_step(stmt);
    if ( errorcode == SQLITE_ROW ) {
        // Column 1 is the value
        const char* text = (const char*)sqlite3_column_text(stmt, 0);
        auto val = zeek::detail::ValFromJSON(text, val_type, Func::nil);
        sqlite3_reset(stmt);
        if ( std::holds_alternative<ValPtr>(val) ) {
            ValPtr val_v = std::get<ValPtr>(val);
            return val_v;
        }
        else {
            return nonstd::unexpected<std::string>(std::get<std::string>(val));
        }
    }

    return nonstd::unexpected<std::string>(util::fmt("Failed to find row for key: %s", sqlite3_errstr(errorcode)));
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult SQLite::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( ! db )
        return "Database was not open";

    auto json_key = key->ToJSON();
    auto stmt = prepared_stmts["erase"];

    auto key_str = json_key->ToStdStringView();
    if ( auto res = checkError(sqlite3_bind_text(stmt, 1, key_str.data(), key_str.size(), SQLITE_STATIC));
         res.has_value() ) {
        sqlite3_reset(stmt);
        return res;
    }

    if ( auto res = checkError(sqlite3_step(stmt)); res.has_value() ) {
        return res;
    }

    return std::nullopt;
}

void SQLite::Expire() {
    auto stmt = prepared_stmts["expire"];

    if ( auto res = checkError(sqlite3_bind_double(stmt, 1, util::current_time())); res.has_value() ) {
        sqlite3_reset(stmt);
        // TODO: do something with the error here?
    }

    if ( auto res = checkError(sqlite3_step(stmt)); res.has_value() ) {
        // TODO: do something with the error here?
    }
}

// returns true in case of error
ErrorResult SQLite::checkError(int code) {
    if ( code != SQLITE_OK && code != SQLITE_DONE ) {
        std::string msg = util::fmt("SQLite call failed: %s", sqlite3_errmsg(db));
        return msg;
    }

    return std::nullopt;
}

} // namespace zeek::storage::backends::sqlite
