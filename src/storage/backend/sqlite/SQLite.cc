// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/sqlite/SQLite.h"

#include <sys/stat.h>
#include <filesystem>
#include <thread>

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/CompHash.h"
#include "zeek/DebugLogger.h"
#include "zeek/Dict.h"
#include "zeek/Func.h"
#include "zeek/Val.h"
#include "zeek/storage/ReturnCode.h"
#include "zeek/telemetry/Manager.h"

#include "const.bif.netvar_h"

using namespace std::chrono_literals;

namespace zeek::storage::backend::sqlite {

OperationResult SQLite::RunPragma(std::string_view name, std::optional<std::string_view> value,
                                  const StepResultParser& value_parser) {
    char* errorMsg = nullptr;
    std::chrono::milliseconds time_spent = 0ms;

    std::string cmd = util::fmt("pragma %.*s", static_cast<int>(name.size()), name.data());
    if ( value && ! value->empty() )
        cmd += util::fmt(" = %.*s", static_cast<int>(value->size()), value->data());

    DBG_LOG(DBG_STORAGE, "Executing '%s' on %s", cmd.c_str(), full_path.c_str());

    sqlite3_stmt* stmt;
    if ( auto check_res = CheckError(sqlite3_prepare_v2(db, cmd.c_str(), static_cast<int>(cmd.size()), &stmt, nullptr));
         check_res.code != ReturnCode::SUCCESS )
        return check_res;

    OperationResult success_res;

    // Make a unique_ptr out of the statement so we don't have to manually call sqlite3_finalize
    // one it when we return in various places.
    unique_stmt_ptr stmt_ptr{stmt, sqlite3_finalize};

    while ( pragma_timeout == 0ms || time_spent < pragma_timeout ) {
        auto res = Step(stmt, value_parser, true);
        if ( res.code == ReturnCode::SUCCESS ) {
            success_res = std::move(res);
            break;
        }
        else if ( res.code == ReturnCode::TIMEOUT ) {
            // If we got back that the database is busy, it likely means that another process is trying to
            // do their pragmas at startup too. Exponentially back off and try again after a sleep.
            sqlite3_free(errorMsg);
            std::this_thread::sleep_for(pragma_wait_on_busy);
            time_spent += pragma_wait_on_busy;
        }
        else {
            std::string err =
                util::fmt("Error while executing '%s': %s (%d)", cmd.c_str(), sqlite3_errmsg(db), sqlite3_errcode(db));
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

    return success_res;
}

storage::BackendPtr SQLite::Instantiate() { return make_intrusive<SQLite>(); }

std::string SQLite::DoGetConfigMetricsLabel() const {
    std::string tag = util::fmt("%s-%s", full_path.c_str(), table_name.c_str());
    return tag;
}

/**
 * Called by the manager system to open the backend.
 */
OperationResult SQLite::DoOpen(OpenResultCallback* cb, RecordValPtr options) {
    // Allow connections to same DB to use single data/schema cache. Also
    // allows simultaneous writes to one file.
#ifndef ZEEK_TSAN
    sqlite3_enable_shared_cache(1);
#endif

    RecordValPtr backend_options = options->GetField<RecordVal>("sqlite");
    StringValPtr path = backend_options->GetField<StringVal>("database_path");
    full_path = std::filesystem::path(path->ToStdString()).string();
    table_name = backend_options->GetField<StringVal>("table_name")->ToStdString();

    auto busy_timeout = backend_options->GetField<IntervalVal>("busy_timeout")->Get();

    auto pragma_timeout_val = backend_options->GetField<IntervalVal>("pragma_timeout");
    pragma_timeout = std::chrono::milliseconds(static_cast<int64_t>(pragma_timeout_val->Get() * 1000));

    auto pragma_wait_val = backend_options->GetField<IntervalVal>("pragma_wait_on_busy");
    pragma_wait_on_busy = std::chrono::milliseconds(static_cast<int64_t>(pragma_wait_val->Get() * 1000));

    if ( auto open_res =
             CheckError(sqlite3_open_v2(full_path.c_str(), &db,
                                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr));
         open_res.code != ReturnCode::SUCCESS ) {
        sqlite3_close_v2(db);
        db = nullptr;
        return open_res;
    }

    sqlite3_busy_timeout(db, busy_timeout * 1000);

    auto pragmas = backend_options->GetField<TableVal>("pragma_commands");
    for ( const auto& iter : *(pragmas->Get()) ) {
        auto k = iter.GetHashKey();
        auto vl = pragmas->GetTableHash()->RecoverVals(*k);

        auto ks = vl->AsListVal()->Idx(0)->AsStringVal();
        auto ks_sv = ks->ToStdStringView();

        if ( ks_sv == "busy_timeout" )
            continue;

        auto vs = iter.value->GetVal()->AsStringVal();
        auto vs_sv = vs->ToStdStringView();

        auto pragma_res = RunPragma(ks_sv, vs_sv);
        if ( pragma_res.code != ReturnCode::SUCCESS ) {
            Error(pragma_res.err_str.c_str());
            Close(nullptr);
            return pragma_res;
        }
    }

    // Open a second connection to the database. This one is used for expiration and exists to prevent
    // simultaneous multi-threaded access to the same connection.
    if ( auto open_res =
             CheckError(sqlite3_open_v2(full_path.c_str(), &expire_db,
                                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr));
         open_res.code != ReturnCode::SUCCESS ) {
        Close(nullptr);
        return open_res;
    }

    sqlite3_busy_timeout(expire_db, busy_timeout * 1000);

    std::string cmd = "create table if not exists " + table_name + " (";
    cmd.append("key_str blob primary key, value_str blob not null, expire_time real);");

    char* errorMsg = nullptr;
    if ( int res = sqlite3_exec(db, cmd.c_str(), nullptr, nullptr, &errorMsg); res != SQLITE_OK ) {
        std::string err = util::fmt("Error executing table creation statement: (%d) %s", res, errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        Close(nullptr);
        return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
    }

    sqlite3_free(errorMsg);

    // Create a table for controlling expiration contention. The ukey column here ensures that only
    // one row exists for this backend's table.
    cmd = util::fmt("create table if not exists zeek_storage_expiry_runs (ukey primary key, last_run double);");
    if ( int res = sqlite3_exec(db, cmd.c_str(), nullptr, nullptr, &errorMsg); res != SQLITE_OK ) {
        std::string err = util::fmt("Error executing table creation statement: (%d) %s", res, errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        Close(nullptr);
        return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
    }

    sqlite3_free(errorMsg);

    // Attempt to insert an initial value into the table if this is the first run with
    // this file. This may result in a SQLITE_CONSTRAINT if the row already exists. That's
    // not an error, as it's possible if the file already existed.
    cmd = util::fmt("insert into zeek_storage_expiry_runs (ukey, last_run) values('%s', 0);", table_name.c_str());
    if ( int res = sqlite3_exec(db, cmd.c_str(), nullptr, nullptr, &errorMsg);
         res != SQLITE_OK && res != SQLITE_CONSTRAINT ) {
        std::string err =
            util::fmt("Error inserting initial row into expiration control table: (%d) %s", res, errorMsg);
        Error(err.c_str());
        sqlite3_free(errorMsg);
        Close(nullptr);
        return {ReturnCode::INITIALIZATION_FAILED, std::move(err)};
    }

    sqlite3_free(errorMsg);

    static std::array<std::pair<std::string, sqlite3*>, 8> statements =
        {// Normal put
         std::make_pair(util::fmt("insert into %s (key_str, value_str, expire_time) values(?, ?, ?) "
                                  "ON CONFLICT(key_str) DO UPDATE SET value_str=?, expire_time=? "
                                  "WHERE expire_time > 0.0 AND expire_time < ?",
                                  table_name.c_str()),
                        db),
         // Put with forced overwrite
         std::make_pair(util::fmt("insert into %s (key_str, value_str, expire_time) values(?, ?, ?) "
                                  "ON CONFLICT(key_str) DO UPDATE SET value_str=?, expire_time=?",
                                  table_name.c_str()),
                        db),
         // Get
         std::make_pair(util::fmt("select value_str, expire_time from %s where key_str=? and "
                                  "(expire_time > ? OR expire_time == 0.0)",
                                  table_name.c_str()),
                        db),
         // Erase
         std::make_pair(util::fmt("delete from %s where key_str=?", table_name.c_str()), db),
         // Check for expired entries
         std::make_pair(
             util::fmt("select count(*) from %s where expire_time > 0 and expire_time != 0 and expire_time <= ?",
                       table_name.c_str()),
             expire_db),
         // Remove expired entries
         std::make_pair(util::fmt("delete from %s where expire_time > 0 and expire_time != 0 and expire_time <= ?",
                                  table_name.c_str()),
                        expire_db),
         // Get the last time expiry ran
         std::make_pair(util::fmt("select last_run from zeek_storage_expiry_runs where ukey = '%s'",
                                  table_name.c_str()),
                        expire_db),
         // Update the last time expiry ran
         std::make_pair(util::fmt("update zeek_storage_expiry_runs set last_run = ? where ukey = '%s'",
                                  table_name.c_str()),
                        expire_db)};

    std::vector<unique_stmt_ptr> stmt_ptrs;
    int i = 0;
    for ( const auto& [stmt, stmt_db] : statements ) {
        sqlite3_stmt* ps;
        if ( auto prep_res =
                 CheckError(sqlite3_prepare_v2(stmt_db, stmt.c_str(), static_cast<int>(stmt.size()), &ps, nullptr));
             prep_res.code != ReturnCode::SUCCESS ) {
            Close(nullptr);
            return prep_res;
        }

        stmt_ptrs.emplace_back(ps, sqlite3_finalize);
    }

    put_stmt = std::move(stmt_ptrs[0]);
    put_update_stmt = std::move(stmt_ptrs[1]);
    get_stmt = std::move(stmt_ptrs[2]);
    erase_stmt = std::move(stmt_ptrs[3]);
    check_expire_stmt = std::move(stmt_ptrs[4]);
    expire_stmt = std::move(stmt_ptrs[5]);
    get_expiry_last_run_stmt = std::move(stmt_ptrs[6]);
    update_expiry_last_run_stmt = std::move(stmt_ptrs[7]);

    page_count_metric =
        telemetry_mgr->GaugeInstance("zeek", "storage_sqlite_database_size", {{"config", GetConfigMetricsLabel()}},
                                     "Storage sqlite backend value of page_count pragma", "pages", [this]() {
                                         static auto double_parser = [](sqlite3_stmt* stmt) -> OperationResult {
                                             double val = sqlite3_column_double(stmt, 0);
                                             return {ReturnCode::SUCCESS, "", make_intrusive<DoubleVal>(val)};
                                         };

                                         auto res = RunPragma("page_count", std::nullopt, double_parser);
                                         if ( res.code == ReturnCode::SUCCESS ) {
                                             last_page_count_value = cast_intrusive<DoubleVal>(res.value)->Get();
                                         }

                                         return last_page_count_value;
                                     });

    file_size_metric =
        telemetry_mgr->GaugeInstance("zeek", "storage_sqlite_database_size", {{"config", GetConfigMetricsLabel()}},
                                     "Storage sqlite backend database file size on disk", "bytes", [this]() {
                                         struct stat s{0};
                                         if ( int ret = stat(full_path.c_str(), &s); ret == 0 ) {
                                             last_file_size_value = static_cast<double>(s.st_size);
                                         }

                                         return last_file_size_value;
                                     });

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
        check_expire_stmt.reset();
        expire_stmt.reset();
        get_expiry_last_run_stmt.reset();
        update_expiry_last_run_stmt.reset();

        char* errmsg;
        if ( int res = sqlite3_exec(db, "pragma optimize", nullptr, nullptr, &errmsg);
             res != SQLITE_OK && res != SQLITE_BUSY ) {
            // We're shutting down so capture the error message here for informational
            // reasons, but don't do anything else with it.
            op_res = {ReturnCode::DISCONNECTION_FAILED, util::fmt("Sqlite failed to optimize at shutdown: %s", errmsg)};
            sqlite3_free(errmsg);
        }

        if ( int res = sqlite3_close_v2(db); res != SQLITE_OK ) {
            op_res.code = ReturnCode::DISCONNECTION_FAILED;
            if ( op_res.err_str.empty() )
                op_res.err_str = "Sqlite could not close main db connection";
        }

        db = nullptr;

        if ( int res = sqlite3_close_v2(expire_db); res != SQLITE_OK ) {
            op_res.code = ReturnCode::DISCONNECTION_FAILED;
            if ( op_res.err_str.empty() )
                op_res.err_str = "Sqlite could not close expire db connection";
        }

        expire_db = nullptr;
        sqlite3_free(errmsg);
    }

    if ( page_count_metric )
        page_count_metric->RemoveCallback();

    if ( file_size_metric )
        file_size_metric->RemoveCallback();

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
    if ( overwrite )
        stmt = unique_stmt_ptr(put_update_stmt.get(), sqlite3_reset);
    else
        stmt = unique_stmt_ptr(put_stmt.get(), sqlite3_reset);

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

    if ( auto res = CheckError(sqlite3_bind_blob(stmt.get(), 4, val_data->data(), val_data->size(), SQLITE_STATIC));
         res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    // This duplicates the above binding, but it's to overwrite the expiration time on the entry.
    if ( auto res = CheckError(sqlite3_bind_double(stmt.get(), 5, expiration_time)); res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    if ( ! overwrite )
        if ( auto res = CheckError(sqlite3_bind_double(stmt.get(), 6, run_state::network_time));
             res.code != ReturnCode::SUCCESS ) {
            return res;
        }

    auto step_result = Step(stmt.get(), nullptr);
    if ( ! overwrite )
        if ( step_result.code == ReturnCode::SUCCESS ) {
            int changed = sqlite3_changes(db);
            if ( changed == 0 )
                step_result.code = ReturnCode::KEY_EXISTS;
        }

    IncBytesWrittenMetric(val_data->size());

    return step_result;
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

    if ( auto res = CheckError(sqlite3_bind_double(stmt.get(), 2, run_state::network_time));
         res.code != ReturnCode::SUCCESS ) {
        return res;
    }

    auto value_parser = [this](sqlite3_stmt* stmt) -> OperationResult {
        auto blob = static_cast<const std::byte*>(sqlite3_column_blob(stmt, 0));
        size_t blob_size = sqlite3_column_bytes(stmt, 0);
        IncBytesReadMetric(blob_size);

        auto val = serializer->Unserialize({blob, blob_size}, val_type);

        if ( val )
            return {ReturnCode::SUCCESS, "", val.value()};

        return {ReturnCode::OPERATION_FAILED, val.error()};
    };

    return Step(stmt.get(), value_parser);
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

    return Step(stmt.get(), nullptr);
}

/**
 * Removes any entries in the backend that have expired. Can be overridden by
 * derived classes.
 */
void SQLite::DoExpire(double current_network_time) {
    int status;
    char* errMsg = nullptr;
    unique_stmt_ptr stmt;

    // Begin an exclusive transaction here to lock the database for this one process. That
    // will ensure there isn't a TOCTOU bug in the time check below.
    while ( true ) {
        status = sqlite3_exec(expire_db, "begin immediate transaction", nullptr, nullptr, &errMsg);
        sqlite3_free(errMsg);

        if ( status == SQLITE_OK )
            break;
        else
            // If any other status is returned here, give up. Notably, this includes
            // SQLITE_BUSY which will be returned if there was already a transaction
            // running. If one node got in and made the transaction, expiration is
            // happening so the rest don't need to retry.
            return;
    }

    // Automatically rollback the transaction when this object is deleted.
    auto deferred_rollback = util::Deferred([this]() {
        char* errMsg = nullptr;
        if ( int status = sqlite3_exec(expire_db, "rollback transaction", nullptr, nullptr, &errMsg);
             status != SQLITE_OK )
            reporter->Warning("SQLite backend failed to rollback transaction during expiration: %s", errMsg);

        sqlite3_free(errMsg);
    });

    // Check if there's anything to expire.
    stmt = unique_stmt_ptr(check_expire_stmt.get(), sqlite3_reset);
    status = sqlite3_bind_double(stmt.get(), 1, current_network_time);
    while ( status != SQLITE_ROW ) {
        status = sqlite3_step(stmt.get());
        if ( status == SQLITE_ROW ) {
            auto num_to_expire = sqlite3_column_int(stmt.get(), 0);

            DBG_LOG(DBG_STORAGE, "Expiration has %d elements to expire", num_to_expire);
            if ( num_to_expire == 0 )
                return;
        }
        else
            return;
    }

    // Check if the expiration control key is less than the interval. Exit if not.
    stmt = unique_stmt_ptr(get_expiry_last_run_stmt.get(), sqlite3_reset);
    status = SQLITE_OK;
    while ( status != SQLITE_ROW ) {
        status = sqlite3_step(stmt.get());
        if ( status == SQLITE_ROW ) {
            double last_run = sqlite3_column_double(stmt.get(), 0);

            DBG_LOG(DBG_STORAGE, "Expiration last run: %f  diff: %f  interval: %f", last_run,
                    current_network_time - last_run, zeek::BifConst::Storage::expire_interval);

            if ( current_network_time > 0 &&
                 (current_network_time - last_run) < zeek::BifConst::Storage::expire_interval )
                return;
        }
        else
            return;
    }

    // Update the expiration control key
    stmt = unique_stmt_ptr(update_expiry_last_run_stmt.get(), sqlite3_reset);
    status = sqlite3_bind_double(stmt.get(), 1, current_network_time);
    if ( status != SQLITE_OK ) {
        std::string err =
            util::fmt("Error preparing statement to update expiration control time: %s", sqlite3_errmsg(expire_db));
        DBG_LOG(DBG_STORAGE, "%s", err.c_str());
        Error(err.c_str());
        sqlite3_free(errMsg);
        return;
    }

    status = sqlite3_step(stmt.get());
    if ( status != SQLITE_ROW && status != SQLITE_DONE ) {
        std::string err = util::fmt("Error updating expiration control time: %s", errMsg);
        DBG_LOG(DBG_STORAGE, "%s", err.c_str());
        Error(err.c_str());
        sqlite3_free(errMsg);
        return;
    }

    // Delete the values.
    stmt = unique_stmt_ptr(expire_stmt.get(), sqlite3_reset);

    status = sqlite3_bind_double(stmt.get(), 1, current_network_time);
    if ( status != SQLITE_OK ) {
        std::string err = util::fmt("Error preparing statement to expire elements: %s", sqlite3_errmsg(expire_db));
        DBG_LOG(DBG_STORAGE, "%s", err.c_str());
        Error(err.c_str());
        sqlite3_free(errMsg);
        return;
    }

    status = sqlite3_step(stmt.get());
    if ( status != SQLITE_ROW && status != SQLITE_DONE ) {
        std::string err = util::fmt("Error expiring elements: %s", sqlite3_errmsg(expire_db));
        DBG_LOG(DBG_STORAGE, "%s", err.c_str());
        Error(err.c_str());
    }

    // Get the number of changes from the delete statement. This should be identical to
    // the num_to_expire value earlier because we're under a transaction, but this should
    // be the exact number that changed.
    int changes = sqlite3_changes(db);
    IncExpiredEntriesMetric(changes);

    status = sqlite3_exec(expire_db, "commit transaction", nullptr, nullptr, &errMsg);
    if ( status != SQLITE_OK )
        reporter->Warning("SQLite backend failed to commit transaction during expiration: %s", errMsg);

    sqlite3_free(errMsg);

    // Don't try to rollback the transaction we just committed, since sqlite will just
    // report an error.
    deferred_rollback.Cancel();
}

// returns true in case of error
OperationResult SQLite::CheckError(int code) {
    if ( code != SQLITE_OK && code != SQLITE_DONE ) {
        return {ReturnCode::OPERATION_FAILED, util::fmt("SQLite call failed: %s", sqlite3_errmsg(db)), nullptr};
    }

    return {ReturnCode::SUCCESS};
}

OperationResult SQLite::Step(sqlite3_stmt* stmt, const StepResultParser& parser, bool is_pragma) {
    OperationResult ret;

    int step_status = sqlite3_step(stmt);
    if ( step_status == SQLITE_ROW ) {
        if ( parser )
            ret = parser(stmt);
        else if ( ! is_pragma )
            ret = {ReturnCode::OPERATION_FAILED, "sqlite3_step should not have returned a value"};
        else
            // For most pragmas we don't care about the output, so we don't pass a parser. We still
            // may get a row as a response, but we can discard it and just return SUCCESS.
            ret = {ReturnCode::SUCCESS};
    }
    else if ( step_status == SQLITE_DONE ) {
        if ( parser )
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
