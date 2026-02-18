// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/storage/Backend.h"

// Forward declare these to avoid including libpq-fe.h here
struct pg_conn;
using PGconn = struct pg_conn;
struct pg_result;
using PGresult = struct pg_result;

namespace zeek::storage::backend::postgresql {

class PostgreSQL final : public Backend {
public:
    PostgreSQL() : Backend(SupportedModes::SYNC, "POSTGRESQL") {}
    ~PostgreSQL() override;

    static BackendPtr Instantiate();

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return conn != nullptr; }

private:
    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(ResultCallback* cb) override;
    OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                          double expiration_time) override;
    OperationResult DoGet(ResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(ResultCallback* cb, ValPtr key) override;
    void DoExpire(double current_network_time) override;
    std::string DoGetConfigMetricsLabel() const override;

    /**
     * Checks whether a status code returned by a PostgreSQL call is a success.
     *
     * @return A result structure containing a result code and an optional error
     * string based on the status code.
     */
    OperationResult CheckError(PGresult* result, bool expect_result = false);

    /**
     * Helper to clear a PGresult pointer.
     */
    void ClearResult(PGresult* result);

    /**
     * Execute a prepared statement with parameters.
     */
    OperationResult ExecPrepared(const char* stmt_name, int n_params, const char* const* param_values,
                                 const int* param_lengths, const int* param_formats);

    PGconn* conn = nullptr;
    PGconn* expire_conn = nullptr;

    std::string connection_string;
    std::string table_name;

    // Prepared statement names
    static constexpr const char* PUT_STMT = "put_stmt";
    static constexpr const char* PUT_UPDATE_STMT = "put_update_stmt";
    static constexpr const char* GET_STMT = "get_stmt";
    static constexpr const char* ERASE_STMT = "erase_stmt";
    static constexpr const char* CHECK_EXPIRE_STMT = "check_expire_stmt";
    static constexpr const char* EXPIRE_STMT = "expire_stmt";
    static constexpr const char* GET_EXPIRY_LAST_RUN_STMT = "get_expiry_last_run_stmt";
    static constexpr const char* UPDATE_EXPIRY_LAST_RUN_STMT = "update_expiry_last_run_stmt";

    telemetry::GaugePtr table_size_metric;
    telemetry::GaugePtr row_count_metric;

    double last_table_size_value = 0.0;
    double last_row_count_value = 0.0;
};

} // namespace zeek::storage::backend::postgresql
