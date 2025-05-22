// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/sqlite/SQLite.h"

#include <thread>

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/CompHash.h"
#include "zeek/DebugLogger.h"
#include "zeek/Dict.h"
#include "zeek/Func.h"
#include "zeek/Val.h"
#include "zeek/storage/ReturnCode.h"

using namespace std::chrono_literals;

namespace zeek::storage::backend::sqlite {

OperationResult SQLite::RunPragma(std::string_view name, std::optional<std::string_view> value) {
    char* errorMsg = nullptr;
    std::chrono::milliseconds time_spent = 0ms;

    std::string cmd = util::fmt("pragma %.*s", static_cast<int>(name.size()), name.data());
    if ( value && ! value->empty() )
        cmd += util::fmt(" = %.*s", static_cast<int>(value->size()), value->data());

    DBG_LOG(DBG_STORAGE, "Executing '%s' on %s", cmd.c_str(), full_path.c_str());

    while ( pragma_timeout == 0ms || time_spent < pragma_timeout ) {
        int res = sqlite3_exec(db, cmd.c_str(), NULL, NULL, &errorMsg);
        if ( res == SQLITE_OK ) {
            break;
        }
        else if ( res == SQLITE_BUSY ) {
            // If we got back that the database is busy, it likely means that another process is trying to
            // do their pragmas at startup too. Exponentially back off and try again after a sleep.
            sqlite3_free(errorMsg);
            std::this_thread::sleep_for(pragma_wait_on_busy);
            time_spent += pragma_wait_on_busy;
        }
        else {
            std::string err = util::fmt("Error while executing '%s': %s (%d)", cmd.c_str(), errorMsg, res);
            sqlite3_free(errorMsg);
            DBG_LOG(DBG_STORAGE, "%s", err.c_str());
            return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
        }
    }

    if ( pragma_timeout != 0ms && time_spent >= pragma_timeout ) {
        std::string err = util::fmt("Database was busy while executing '%s'", cmd.c_str());
        DBG_LOG(DBG_STORAGE, "%s", err.c_str());
        return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
    }

    DBG_LOG(DBG_STORAGE, "'%s' successful", cmd.c_str());

    return {ReturnCode::SUCCESS};
}

storage::BackendPtr SQLite::Instantiate() { return make_intrusive<SQLite>(); }

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

    auto pragma_timeout_val = backend_options->GetField<IntervalVal>("pragma_timeout");
    pragma_timeout = std::chrono::milliseconds(static_cast<int64_t>(pragma_timeout_val->Get() * 1000));

    auto pragma_wait_val = backend_options->GetField<IntervalVal>("pragma_wait_on_busy");
    pragma_wait_on_busy = std::chrono::milliseconds(static_cast<int64_t>(pragma_wait_val->Get() * 1000));

    if ( auto open_res =
             CheckError(sqlite3_open_v2(full_path.c_str(), &db,
                                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL));
         open_res.code != ReturnCode::SUCCESS ) {
        sqlite3_close_v2(db);
        db = nullptr;
        return open_res;
    }

    // TODO: Should we use sqlite3_busy_timeout here instead of using the pragma? That would
    // at least let us skip over one. The busy timeout is per-connection as well, so it'll
    // never fail to run like the other pragmas can.
    //    sqlite3_busy_timeout(db, 2000);

    auto pragmas = backend_options->GetField<TableVal>("pragma_commands");
    for ( const auto& iter : *(pragmas->Get()) ) {
        auto k = iter.GetHashKey();
        auto v = iter.value;
        auto vl = pragmas->GetTableHash()->RecoverVals(*k);

        auto ks = vl->AsListVal()->Idx(0)->AsStringVal();
        auto ks_sv = ks->ToStdStringView();
        auto vs = v->GetVal()->AsStringVal();
        auto vs_sv = vs->ToStdStringView();

        auto pragma_res = RunPragma(ks_sv, vs_sv);
        if ( pragma_res.code != ReturnCode::SUCCESS ) {
            Error(pragma_res.err_str.c_str());
            return pragma_res;
        }
    }

    std::string create = "create table if not exists " + table_name + " (";
    create.append("key_str blob primary key, value_str blob not null, expire_time real);");

    char* errorMsg = nullptr;
    if ( int res = sqlite3_exec(db, create.c_str(), NULL, NULL, &errorMsg); res != SQLITE_OK ) {
        std::string err = util::fmt("Error executing table creation statement: (%d) %s", res, errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        Close(nullptr);
        return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
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
        if ( auto prep_res = CheckError(sqlite3_prepare_v2(db, stmt.c_str(), static_cast<int>(stmt.size()), &ps, NULL));
             prep_res.code != ReturnCode::SUCCESS ) {
            Close(nullptr);
            return prep_res;
        }

        stmt_ptrs[i++] = unique_stmt_ptr(ps, sqlite3_finalize);
    }

    put_stmt = std::move(stmt_ptrs[0]);
    put_update_stmt = std::move(stmt_ptrs[1]);
    get_stmt = std::move(stmt_ptrs[2]);
    erase_stmt = std::move(stmt_ptrs[3]);
    expire_stmt = std::move(stmt_ptrs[4]);

    return {ReturnCode::SUCCESS};
}

/**
 * Finalizes the backend when it's being closed.
 */
OperationResult SQLite::DoClose(ResultCallback* cb) {
    OperationResult op_res{ReturnCode::SUCCESS};

    if ( db ) {
        // These will all call sqlite3_finalize as they're deleted.
        put_stmt.reset();
        put_update_stmt.reset();
        get_stmt.reset();
        erase_stmt.reset();
        expire_stmt.reset();

        char* errmsg;
        if ( int res = sqlite3_exec(db, "pragma optimize", NULL, NULL, &errmsg);
             res != SQLITE_OK && res != SQLITE_BUSY ) {
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

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    unique_stmt_ptr stmt;
    if ( ! overwrite )
        stmt = unique_stmt_ptr(put_stmt.get(), sqlite3_reset);
    else
        stmt = unique_stmt_ptr(put_update_stmt.get(), sqlite3_reset);

    if ( auto res = CheckError(sqlite3_bind_blob(stmt.get(), 1, key_data->data(), key_data->size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    auto val_data = serializer->Serialize(value);
    if ( ! val_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize value"};

    if ( auto res = CheckError(sqlite3_bind_blob(stmt.get(), 2, val_data->data(), val_data->size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    if ( auto res = CheckError(sqlite3_bind_double(stmt.get(), 3, expiration_time)); res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    if ( overwrite ) {
        if ( auto res = CheckError(sqlite3_bind_blob(stmt.get(), 4, val_data->data(), val_data->size(), SQLITE_STATIC));
             res.code != ReturnCode::SUCCESS ) {
            return res;
        }
    }

    return Step(stmt.get(), false);
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
OperationResult SQLite::DoGet(ResultCallback* cb, ValPtr key) {
    if ( ! db )
        return {ReturnCode::NOT_CONNECTED};

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    auto stmt = unique_stmt_ptr(get_stmt.get(), sqlite3_reset);

    if ( auto res = CheckError(sqlite3_bind_blob(stmt.get(), 1, key_data->data(), key_data->size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    return Step(stmt.get(), true);
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
OperationResult SQLite::DoErase(ResultCallback* cb, ValPtr key) {
    if ( ! db )
        return {ReturnCode::NOT_CONNECTED};

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    auto stmt = unique_stmt_ptr(erase_stmt.get(), sqlite3_reset);

    if ( auto res = CheckError(sqlite3_bind_blob(stmt.get(), 1, key_data->data(), key_data->size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    return Step(stmt.get(), false);
}

/**
 * Removes any entries in the backend that have expired. Can be overridden by
 * derived classes.
 */
void SQLite::DoExpire(double current_network_time) {
    auto stmt = unique_stmt_ptr(expire_stmt.get(), sqlite3_reset);

    int status = sqlite3_bind_double(stmt.get(), 1, current_network_time);
    if ( status != SQLITE_OK ) {
        // TODO: do something with the error?
        return;
    }

    status = sqlite3_step(stmt.get());
    if ( status != SQLITE_ROW ) {
        // TODO: should this return an error somehow? Reporter warning?
    }
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
            auto blob = static_cast<const std::byte*>(sqlite3_column_blob(stmt, 0));
            size_t blob_size = sqlite3_column_bytes(stmt, 0);

            auto val = serializer->Unserialize({blob, blob_size}, val_type);

            if ( val )
                ret = {ReturnCode::SUCCESS, "", val.value()};
            else
                ret = {ReturnCode::OPERATION_FAILED, val.error()};
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
    else if ( step_status == SQLITE_BUSY || step_status == SQLITE_LOCKED )
        // TODO: this could retry a number of times instead of just failing
        ret = {ReturnCode::TIMEOUT};
    else if ( step_status == SQLITE_CONSTRAINT )
        ret = {ReturnCode::KEY_EXISTS};
    else
        ret = {ReturnCode::OPERATION_FAILED};

    return ret;
}

} // namespace zeek::storage::backend::sqlite
