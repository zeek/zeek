// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/postgresql/PostgreSQL.h"

#include <libpq-fe.h>
#include <cstring>

#include "zeek/DebugLogger.h"
#include "zeek/Val.h"
#include "zeek/storage/ReturnCode.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/util.h"

#include "const.bif.netvar_h"

namespace zeek::storage::backend::postgresql {

PostgreSQL::~PostgreSQL() {
    if ( conn ) {
        PQfinish(conn);
        conn = nullptr;
    }
    if ( expire_conn ) {
        PQfinish(expire_conn);
        expire_conn = nullptr;
    }
}

BackendPtr PostgreSQL::Instantiate() { return make_intrusive<PostgreSQL>(); }

std::string PostgreSQL::DoGetConfigMetricsLabel() const {
    std::string tag = util::fmt("%s-%s", connection_string.c_str(), table_name.c_str());
    return tag;
}

OperationResult PostgreSQL::DoOpen(OpenResultCallback* cb, RecordValPtr options) {
    RecordValPtr backend_options = options->GetField<RecordVal>("postgresql");
    StringValPtr conninfo = backend_options->GetField<StringVal>("connection_string");
    connection_string = conninfo->ToStdString();
    table_name = backend_options->GetField<StringVal>("table_name")->ToStdString();

    // Open main connection
    conn = PQconnectdb(connection_string.c_str());
    if ( PQstatus(conn) != CONNECTION_OK ) {
        std::string err = util::fmt("PostgreSQL connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        conn = nullptr;
        return {ReturnCode::CONNECTION_FAILED, std::move(err)};
    }

    // Open second connection for expiration
    expire_conn = PQconnectdb(connection_string.c_str());
    if ( PQstatus(expire_conn) != CONNECTION_OK ) {
        std::string err = util::fmt("PostgreSQL expiration connection failed: %s", PQerrorMessage(expire_conn));
        PQfinish(expire_conn);
        expire_conn = nullptr;
        PQfinish(conn);
        conn = nullptr;
        return {ReturnCode::CONNECTION_FAILED, std::move(err)};
    }

    // Create table if it doesn't exist
    std::string create_table_sql = util::
        fmt("CREATE TABLE IF NOT EXISTS %s ("
            "key_str BYTEA PRIMARY KEY, "
            "value_str BYTEA NOT NULL, "
            "expire_time DOUBLE PRECISION)",
            table_name.c_str());

    PGresult* result = PQexec(conn, create_table_sql.c_str());
    if ( auto check_res = CheckError(result); check_res.code != ReturnCode::SUCCESS ) {
        ClearResult(result);
        DoClose(nullptr);
        return check_res;
    }
    ClearResult(result);

    // Create expiry control table
    std::string create_expiry_table_sql =
        "CREATE TABLE IF NOT EXISTS zeek_storage_expiry_runs ("
        "ukey TEXT PRIMARY KEY, "
        "last_run DOUBLE PRECISION)";

    result = PQexec(conn, create_expiry_table_sql.c_str());
    if ( auto check_res = CheckError(result); check_res.code != ReturnCode::SUCCESS ) {
        ClearResult(result);
        DoClose(nullptr);
        return check_res;
    }
    ClearResult(result);

    // Insert initial expiry row (ignore if already exists)
    std::string insert_expiry_sql = util::
        fmt("INSERT INTO zeek_storage_expiry_runs (ukey, last_run) "
            "VALUES ('%s', 0) ON CONFLICT (ukey) DO NOTHING",
            table_name.c_str());

    result = PQexec(conn, insert_expiry_sql.c_str());
    if ( auto check_res = CheckError(result); check_res.code != ReturnCode::SUCCESS ) {
        ClearResult(result);
        DoClose(nullptr);
        return check_res;
    }
    ClearResult(result);

    static std::array<std::tuple<std::string, std::string, PGconn*>, 8> statements =
        {// Normal put
         std::make_tuple(util::fmt("INSERT INTO %s (key_str, value_str, expire_time) VALUES ($1, $2, $3) "
                                   "ON CONFLICT (key_str) DO UPDATE SET value_str = $4, expire_time = $5 "
                                   "WHERE %s.expire_time > 0.0 AND %s.expire_time < $6",
                                   table_name.c_str(), table_name.c_str(), table_name.c_str()),
                         PUT_STMT, conn),
         // Put with forced overwrite
         std::make_tuple(util::fmt("INSERT INTO %s (key_str, value_str, expire_time) VALUES ($1, $2, $3) "
                                   "ON CONFLICT (key_str) DO UPDATE SET value_str = $4, expire_time = $5",
                                   table_name.c_str()),
                         PUT_UPDATE_STMT, conn),
         // Get
         std::make_tuple(util::fmt("SELECT value_str, expire_time FROM %s "
                                   "WHERE key_str = $1 AND (expire_time > $2 OR expire_time = 0.0)",
                                   table_name.c_str()),
                         GET_STMT, conn),
         // Erase
         std::make_tuple(util::fmt("DELETE FROM %s WHERE key_str = $1", table_name.c_str()), ERASE_STMT, conn),
         // Check for expired entries
         std::make_tuple(
             util::fmt("SELECT COUNT(*) FROM %s WHERE expire_time > 0 AND expire_time != 0 AND expire_time <= $1",
                       table_name.c_str()),
             CHECK_EXPIRE_STMT, expire_conn),
         // Remove expired entries
         std::make_tuple(util::fmt("DELETE FROM %s WHERE expire_time > 0 AND expire_time != 0 AND expire_time <= $1",
                                   table_name.c_str()),
                         EXPIRE_STMT, expire_conn),
         // Get the time expiry ran
         std::make_tuple(util::fmt("SELECT last_run FROM zeek_storage_expiry_runs WHERE ukey = '%s'",
                                   table_name.c_str()),
                         GET_EXPIRY_LAST_RUN_STMT, expire_conn),
         // Update the last time expiry ran
         std::make_tuple(util::fmt("UPDATE zeek_storage_expiry_runs SET last_run = $1 WHERE ukey = '%s'",
                                   table_name.c_str()),
                         UPDATE_EXPIRY_LAST_RUN_STMT, expire_conn)};

    for ( const auto& [stmt, stmt_name, db] : statements ) {
        result = PQprepare(db, stmt_name.c_str(), stmt.c_str(), 6, nullptr);
        if ( auto check_res = CheckError(result); check_res.code != ReturnCode::SUCCESS ) {
            ClearResult(result);
            DoClose(nullptr);
            return check_res;
        }
        ClearResult(result);
    }

    // Setup metrics
    table_size_metric =
        telemetry_mgr->GaugeInstance("zeek", "storage_postgresql_table_size", {{"config", GetConfigMetricsLabel()}},
                                     "Storage PostgreSQL backend table size on disk", "bytes", [this]() {
                                         std::string size_query =
                                             util::fmt("SELECT pg_total_relation_size('%s')", table_name.c_str());
                                         PGresult* result = PQexec(conn, size_query.c_str());
                                         if ( PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) > 0 ) {
                                             const char* size_str = PQgetvalue(result, 0, 0);
                                             last_table_size_value = std::atof(size_str);
                                         }
                                         PQclear(result);
                                         return last_table_size_value;
                                     });

    row_count_metric =
        telemetry_mgr->GaugeInstance("zeek", "storage_postgresql_row_count", {{"config", GetConfigMetricsLabel()}},
                                     "Storage PostgreSQL backend row count", "rows", [this]() {
                                         std::string count_query =
                                             util::fmt("SELECT COUNT(*) FROM %s", table_name.c_str());
                                         PGresult* result = PQexec(conn, count_query.c_str());
                                         if ( PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) > 0 ) {
                                             const char* count_str = PQgetvalue(result, 0, 0);
                                             last_row_count_value = std::atof(count_str);
                                         }
                                         PQclear(result);
                                         return last_row_count_value;
                                     });

    return {ReturnCode::SUCCESS};
} // namespace zeek::storage::backend::postgresql

OperationResult PostgreSQL::DoClose(ResultCallback* cb) {
    if ( conn ) {
        PQfinish(conn);
        conn = nullptr;
    }

    if ( expire_conn ) {
        PQfinish(expire_conn);
        expire_conn = nullptr;
    }

    if ( table_size_metric )
        table_size_metric->RemoveCallback();

    if ( row_count_metric )
        row_count_metric->RemoveCallback();

    return {ReturnCode::SUCCESS};
}

OperationResult PostgreSQL::DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                                  double expiration_time) {
    if ( ! conn )
        return {ReturnCode::NOT_CONNECTED};

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    auto val_data = serializer->Serialize(value);
    if ( ! val_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize value"};

    std::string expire_time_str = std::to_string(expiration_time);
    std::string network_time_str = std::to_string(run_state::network_time);

    const char* param_values[6];
    int param_lengths[6];
    int param_formats[6];

    param_values[0] = reinterpret_cast<const char*>(key_data->data());
    param_lengths[0] = key_data->size();
    param_formats[0] = 1; // binary

    param_values[1] = reinterpret_cast<const char*>(val_data->data());
    param_lengths[1] = val_data->size();
    param_formats[1] = 1; // binary

    param_values[2] = expire_time_str.c_str();
    param_lengths[2] = expire_time_str.size();
    param_formats[2] = 0; // text

    param_values[3] = reinterpret_cast<const char*>(val_data->data());
    param_lengths[3] = val_data->size();
    param_formats[3] = 1; // binary

    param_values[4] = expire_time_str.c_str();
    param_lengths[4] = expire_time_str.size();
    param_formats[4] = 0; // text

    int n_params;
    const char* stmt_name;

    if ( overwrite ) {
        stmt_name = PUT_UPDATE_STMT;
        n_params = 5;
    }
    else {
        stmt_name = PUT_STMT;
        n_params = 6;
        param_values[5] = network_time_str.c_str();
        param_lengths[5] = network_time_str.size();
        param_formats[5] = 0; // text
    }

    auto result = ExecPrepared(stmt_name, n_params, param_values, param_lengths, param_formats);

    IncBytesWrittenMetric(val_data->size());

    return result;
}

OperationResult PostgreSQL::DoGet(ResultCallback* cb, ValPtr key) {
    if ( ! conn )
        return {ReturnCode::NOT_CONNECTED};

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    std::string network_time_str = std::to_string(run_state::network_time);

    const char* param_values[2];
    int param_lengths[2];
    int param_formats[2];

    param_values[0] = reinterpret_cast<const char*>(key_data->data());
    param_lengths[0] = key_data->size();
    param_formats[0] = 1; // binary

    param_values[1] = network_time_str.c_str();
    param_lengths[1] = network_time_str.size();
    param_formats[1] = 0; // text

    PGresult* result = PQexecPrepared(conn, GET_STMT, 2, param_values, param_lengths, param_formats, 1);

    if ( auto check_res = CheckError(result, true); check_res.code != ReturnCode::SUCCESS ) {
        ClearResult(result);
        return check_res;
    }

    if ( PQntuples(result) == 0 ) {
        ClearResult(result);
        return {ReturnCode::KEY_NOT_FOUND};
    }

    const char* value_blob = PQgetvalue(result, 0, 0);
    int value_len = PQgetlength(result, 0, 0);

    IncBytesReadMetric(value_len);

    auto val = serializer->Unserialize({reinterpret_cast<const std::byte*>(value_blob), static_cast<size_t>(value_len)},
                                       val_type);

    ClearResult(result);

    if ( val )
        return {ReturnCode::SUCCESS, "", val.value()};

    return {ReturnCode::OPERATION_FAILED, val.error()};
}

OperationResult PostgreSQL::DoErase(ResultCallback* cb, ValPtr key) {
    if ( ! conn )
        return {ReturnCode::NOT_CONNECTED};

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    const char* param_values[1];
    int param_lengths[1];
    int param_formats[1];

    param_values[0] = reinterpret_cast<const char*>(key_data->data());
    param_lengths[0] = key_data->size();
    param_formats[0] = 1; // binary

    return ExecPrepared(ERASE_STMT, 1, param_values, param_lengths, param_formats);
}

void PostgreSQL::DoExpire(double current_network_time) {
    if ( ! expire_conn )
        return;

    // Begin transaction
    PGresult* result = PQexec(expire_conn, "BEGIN");
    if ( PQresultStatus(result) != PGRES_COMMAND_OK ) {
        ClearResult(result);
        return;
    }
    ClearResult(result);

    auto deferred_rollback = util::Deferred([this]() {
        PGresult* result = PQexec(expire_conn, "ROLLBACK");
        if ( PQresultStatus(result) != PGRES_COMMAND_OK )
            reporter->Warning("PostgreSQL backend failed to rollback transaction during expiration: %s",
                              PQerrorMessage(expire_conn));
        PQclear(result);
    });

    // Check if there's anything to expire
    std::string network_time_str = std::to_string(current_network_time);
    const char* param_values[1];
    int param_lengths[1];
    int param_formats[1];

    param_values[0] = network_time_str.c_str();
    param_lengths[0] = network_time_str.size();
    param_formats[0] = 0; // text

    result = PQexecPrepared(expire_conn, CHECK_EXPIRE_STMT, 1, param_values, param_lengths, param_formats, 0);

    if ( PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) == 0 ) {
        ClearResult(result);
        return;
    }

    int num_to_expire = std::atoi(PQgetvalue(result, 0, 0));
    ClearResult(result);

    DBG_LOG(DBG_STORAGE, "Expiration has %d elements to expire", num_to_expire);
    if ( num_to_expire == 0 )
        return;

    // Check if expiration should run based on interval
    result = PQexecPrepared(expire_conn, GET_EXPIRY_LAST_RUN_STMT, 0, nullptr, nullptr, nullptr, 0);

    if ( PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) == 0 ) {
        ClearResult(result);
        return;
    }

    double last_run = std::atof(PQgetvalue(result, 0, 0));
    ClearResult(result);

    DBG_LOG(DBG_STORAGE, "Expiration last run: %f  diff: %f  interval: %f", last_run, current_network_time - last_run,
            zeek::BifConst::Storage::expire_interval);

    if ( current_network_time > 0 && (current_network_time - last_run) < zeek::BifConst::Storage::expire_interval )
        return;

    // Update expiration last run time
    result = PQexecPrepared(expire_conn, UPDATE_EXPIRY_LAST_RUN_STMT, 1, param_values, param_lengths, param_formats, 0);

    if ( PQresultStatus(result) != PGRES_COMMAND_OK ) {
        std::string err = util::fmt("Error updating expiration control time: %s", PQerrorMessage(expire_conn));
        DBG_LOG(DBG_STORAGE, "%s", err.c_str());
        Error(err.c_str());
        ClearResult(result);
        return;
    }
    ClearResult(result);

    // Delete expired entries
    result = PQexecPrepared(expire_conn, EXPIRE_STMT, 1, param_values, param_lengths, param_formats, 0);

    if ( PQresultStatus(result) != PGRES_COMMAND_OK ) {
        std::string err = util::fmt("Error expiring elements: %s", PQerrorMessage(expire_conn));
        DBG_LOG(DBG_STORAGE, "%s", err.c_str());
        Error(err.c_str());
        ClearResult(result);
        return;
    }

    int changes = std::atoi(PQcmdTuples(result));
    ClearResult(result);

    IncExpiredEntriesMetric(changes);

    // Commit transaction
    result = PQexec(expire_conn, "COMMIT");
    if ( PQresultStatus(result) != PGRES_COMMAND_OK )
        reporter->Warning("PostgreSQL backend failed to commit transaction during expiration: %s",
                          PQerrorMessage(expire_conn));

    ClearResult(result);

    deferred_rollback.Cancel();
}

OperationResult PostgreSQL::CheckError(PGresult* result, bool expect_result) {
    if ( ! result )
        return {ReturnCode::OPERATION_FAILED, "PostgreSQL query returned null result"};

    ExecStatusType status = PQresultStatus(result);

    // A fatal error can mean a lot of things, but one of them means the server went away. Close
    // the connection and post the event that the server died.
    if ( status == PGRES_FATAL_ERROR ) {
        std::string err = util::fmt("Client disconnected: %s", PQerrorMessage(conn));
        EnqueueBackendLost(err);
        DoClose(nullptr);
        return {ReturnCode::CONNECTION_LOST, std::move(err)};
    }

    if ( expect_result ) {
        if ( status != PGRES_TUPLES_OK ) {
            std::string err = util::fmt("PostgreSQL query failed: %s", PQerrorMessage(conn));
            return {ReturnCode::OPERATION_FAILED, std::move(err)};
        }
    }
    else {
        if ( status != PGRES_COMMAND_OK ) {
            std::string err = util::fmt("PostgreSQL command failed: %s", PQerrorMessage(conn));
            return {ReturnCode::OPERATION_FAILED, std::move(err)};
        }
    }

    return {ReturnCode::SUCCESS};
}

void PostgreSQL::ClearResult(PGresult* result) {
    if ( result )
        PQclear(result);
}

OperationResult PostgreSQL::ExecPrepared(const char* stmt_name, int n_params, const char* const* param_values,
                                         const int* param_lengths, const int* param_formats) {
    PGresult* result = PQexecPrepared(conn, stmt_name, n_params, param_values, param_lengths, param_formats, 0);

    if ( auto check_res = CheckError(result); check_res.code != ReturnCode::SUCCESS ) {
        ClearResult(result);
        return check_res;
    }

    ClearResult(result);
    return {ReturnCode::SUCCESS};
}

} // namespace zeek::storage::backend::postgresql
