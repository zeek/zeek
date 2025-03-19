// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/sqlite/SQLite.h"

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/Func.h"
#include "zeek/Val.h"
#include "zeek/storage/ReturnCode.h"

namespace zeek::storage::backend::sqlite {

storage::BackendPtr SQLite::Instantiate(std::string_view tag) { return make_intrusive<SQLite>(tag); }

/**
 * Called by the manager system to open the backend.
 */
OperationResult SQLite::DoOpen(OpenResultCallback* cb, RecordValPtr options) {
    if ( sqlite3_threadsafe() == 0 ) {
        std::string res =
            "SQLite reports that it is not threadsafe. Zeek needs a threadsafe version of "
            "SQLite. Aborting";
        Error(res.c_str());
        return {ReturnCode::INITIALIZATION_FAILED, std::move(res)};
    }

    // Allow connections to same DB to use single data/schema cache. Also
    // allows simultaneous writes to one file.
#ifndef ZEEK_TSAN
    sqlite3_enable_shared_cache(1);
#endif

    RecordValPtr backend_options = options->GetField<RecordVal>("sqlite");
    StringValPtr path = backend_options->GetField<StringVal>("database_path");
    full_path = zeek::filesystem::path(path->ToStdString()).string();
    table_name = backend_options->GetField<StringVal>("table_name")->ToStdString();

    if ( auto open_res =
             CheckError(sqlite3_open_v2(full_path.c_str(), &db,
                                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL));
         open_res.code != ReturnCode::SUCCESS ) {
        sqlite3_close_v2(db);
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
        Close(nullptr);
        return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
    }

    if ( int res = sqlite3_exec(db, "pragma integrity_check", NULL, NULL, &errorMsg); res != SQLITE_OK ) {
        std::string err = util::fmt("Error executing integrity check: %s", errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        Close(nullptr);
        return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
    }

    auto tuning_params = backend_options->GetField<TableVal>("tuning_params")->ToMap();
    for ( const auto& [k, v] : tuning_params ) {
        auto ks = k->AsListVal()->Idx(0)->AsStringVal();
        auto vs = v->AsStringVal();
        std::string cmd = util::fmt("pragma %s = %s", ks->ToStdStringView().data(), vs->ToStdStringView().data());

        if ( int res = sqlite3_exec(db, cmd.c_str(), NULL, NULL, &errorMsg); res != SQLITE_OK ) {
            std::string err = util::fmt("Error executing tuning pragma statement: %s", errorMsg);
            Error(err.c_str());
            sqlite3_free(errorMsg);
            Close(nullptr);
            return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
        }
    }

    static std::array<std::string, 5> statements =
        {util::fmt("insert into %s (key_str, value_str, expire_time) values(?, ?, ?)", table_name.c_str()),
         util::fmt("insert into %s (key_str, value_str, expire_time) values(?, ?, ?) ON CONFLICT(key_str) "
                   "DO UPDATE SET value_str=?",
                   table_name.c_str()),
         util::fmt("select value_str from %s where key_str=?", table_name.c_str()),
         util::fmt("delete from %s where key_str=?", table_name.c_str()),
         util::fmt("delete from %s where expire_time > 0 and expire_time != 0 and expire_time <= ?",
                   table_name.c_str())};

    std::array<unique_stmt_ptr, 5> stmt_ptrs;
    int i = 0;
    for ( const auto& stmt : statements ) {
        sqlite3_stmt* ps;
        if ( auto prep_res = CheckError(sqlite3_prepare_v2(db, stmt.c_str(), stmt.size(), &ps, NULL));
             prep_res.code != ReturnCode::SUCCESS ) {
            Close(nullptr);
            return prep_res;
        }

        stmt_ptrs[i++] = unique_stmt_ptr(ps, [](sqlite3_stmt* stmt) { sqlite3_finalize(stmt); });
    }

    put_stmt = std::move(stmt_ptrs[0]);
    put_update_stmt = std::move(stmt_ptrs[1]);
    get_stmt = std::move(stmt_ptrs[2]);
    erase_stmt = std::move(stmt_ptrs[3]);
    expire_stmt = std::move(stmt_ptrs[4]);

    sqlite3_busy_timeout(db, 5000);

    return {ReturnCode::SUCCESS};
}

/**
 * Finalizes the backend when it's being closed.
 */
OperationResult SQLite::DoClose(ResultCallback* cb) {
    OperationResult op_res{ReturnCode::SUCCESS};

    if ( db ) {
        put_stmt.reset();
        put_update_stmt.reset();
        get_stmt.reset();
        erase_stmt.reset();
        expire_stmt.reset();

        char* errmsg;
        if ( int res = sqlite3_exec(db, "pragma optimize", NULL, NULL, &errmsg); res != SQLITE_OK ) {
            // We're shutting down so capture the error message here for informational
            // reasons, but don't do anything else with it.
            op_res = {ReturnCode::DISCONNECTION_FAILED, util::fmt("Sqlite failed to optimize at shutdown: %s", errmsg)};
            sqlite3_free(errmsg);
        }

        if ( int res = sqlite3_close_v2(db); res != SQLITE_OK ) {
            if ( op_res.err_str.empty() )
                op_res.err_str = "Sqlite could not close connection";
        }

        db = nullptr;
    }

    return op_res;
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
OperationResult SQLite::DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite, double expiration_time) {
    if ( ! db )
        return {ReturnCode::NOT_CONNECTED};

    auto json_key = key->ToJSON();
    auto json_value = value->ToJSON();

    sqlite3_stmt* stmt;
    if ( ! overwrite )
        stmt = put_stmt.get();
    else
        stmt = put_update_stmt.get();

    auto key_str = json_key->ToStdStringView();
    if ( auto res = CheckError(sqlite3_bind_text(stmt, 1, key_str.data(), key_str.size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        sqlite3_reset(stmt);
        return res;
    }

    auto value_str = json_value->ToStdStringView();
    if ( auto res = CheckError(sqlite3_bind_text(stmt, 2, value_str.data(), value_str.size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        sqlite3_reset(stmt);
        return res;
    }

    if ( auto res = CheckError(sqlite3_bind_double(stmt, 3, expiration_time)); res.code != ReturnCode::SUCCESS ) {
        sqlite3_reset(stmt);
        return res;
    }

    if ( overwrite ) {
        if ( auto res = CheckError(sqlite3_bind_text(stmt, 4, value_str.data(), value_str.size(), SQLITE_STATIC));
             res.code != ReturnCode::SUCCESS ) {
            sqlite3_reset(stmt);
            return res;
        }
    }

    return Step(stmt, false);
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
OperationResult SQLite::DoGet(ResultCallback* cb, ValPtr key) {
    if ( ! db )
        return {ReturnCode::NOT_CONNECTED};

    auto json_key = key->ToJSON();
    auto stmt = get_stmt.get();

    auto key_str = json_key->ToStdStringView();
    if ( auto res = CheckError(sqlite3_bind_text(stmt, 1, key_str.data(), key_str.size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        sqlite3_reset(stmt);
        return res;
    }

    return Step(stmt, true);
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
OperationResult SQLite::DoErase(ResultCallback* cb, ValPtr key) {
    if ( ! db )
        return {ReturnCode::NOT_CONNECTED};

    auto json_key = key->ToJSON();
    auto stmt = erase_stmt.get();

    auto key_str = json_key->ToStdStringView();
    if ( auto res = CheckError(sqlite3_bind_text(stmt, 1, key_str.data(), key_str.size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        sqlite3_reset(stmt);
        return res;
    }

    return Step(stmt, false);
}

/**
 * Removes any entries in the backend that have expired. Can be overridden by
 * derived classes.
 */
void SQLite::DoExpire(double current_network_time) {
    auto stmt = expire_stmt.get();

    if ( auto res = CheckError(sqlite3_bind_double(stmt, 1, current_network_time)); res.code != ReturnCode::SUCCESS ) {
        sqlite3_reset(stmt);
        // TODO: do something with the error here?
    }

    Step(stmt, false);
}

// returns true in case of error
OperationResult SQLite::CheckError(int code) {
    if ( code != SQLITE_OK && code != SQLITE_DONE ) {
        return {ReturnCode::OPERATION_FAILED, util::fmt("SQLite call failed: %s", sqlite3_errmsg(db)), nullptr};
    }

    return {ReturnCode::SUCCESS};
}

OperationResult SQLite::Step(sqlite3_stmt* stmt, bool parse_value) {
    OperationResult ret;

    int step_status = sqlite3_step(stmt);
    if ( step_status == SQLITE_ROW ) {
        if ( parse_value ) {
            // Column 1 is the value
            const char* text = (const char*)sqlite3_column_text(stmt, 0);
            auto val = zeek::detail::ValFromJSON(text, val_type, Func::nil);
            sqlite3_reset(stmt);
            if ( std::holds_alternative<ValPtr>(val) ) {
                ValPtr val_v = std::get<ValPtr>(val);
                ret = {ReturnCode::SUCCESS, "", val_v};
            }
            else {
                ret = {ReturnCode::OPERATION_FAILED, std::get<std::string>(val)};
            }
        }
        else {
            ret = {ReturnCode::OPERATION_FAILED, "sqlite3_step should not have returned a value"};
        }
    }
    else if ( step_status == SQLITE_DONE ) {
        if ( parse_value )
            ret = {ReturnCode::KEY_NOT_FOUND};
        else
            ret = {ReturnCode::SUCCESS};
    }
    else if ( step_status == SQLITE_BUSY )
        // TODO: this could retry a number of times instead of just failing
        ret = {ReturnCode::TIMEOUT};
    else
        ret = {ReturnCode::OPERATION_FAILED};

    sqlite3_reset(stmt);

    return ret;
}

} // namespace zeek::storage::backend::sqlite
