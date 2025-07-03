// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <chrono>

#include "zeek/storage/Backend.h"

// Forward declare these to avoid including sqlite3.h here
struct sqlite3;
struct sqlite3_stmt;

namespace zeek::storage::backend::sqlite {

class SQLite final : public Backend {
public:
    SQLite() : Backend(SupportedModes::SYNC, "SQLITE") {}
    ~SQLite() override = default;

    static BackendPtr Instantiate();

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return db != nullptr; }

private:
    using StepResultParser = std::function<OperationResult(sqlite3_stmt*)>;

    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(ResultCallback* cb) override;
    OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                          double expiration_time) override;
    OperationResult DoGet(ResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(ResultCallback* cb, ValPtr key) override;
    void DoExpire(double current_network_time) override;

    /**
     * Checks whether a status code returned by an sqlite call is a success.
     *
     * @return A result structure containing a result code and an optional error
     * string based on the status code.
     */
    OperationResult CheckError(int code);

    /**
     * Abstracts calls to sqlite3_step to properly create an OperationResult
     * structure based on the result.
     */
    OperationResult Step(sqlite3_stmt* stmt, StepResultParser parser);

    /**
     * Helper utility for running pragmas on the database.
     */
    OperationResult RunPragma(std::string_view name, std::optional<std::string_view> value = std::nullopt);

    sqlite3* db = nullptr;
    sqlite3* expire_db = nullptr;

    using sqlite_stmt_func = std::function<void(sqlite3_stmt*)>;
    using unique_stmt_ptr = std::unique_ptr<sqlite3_stmt, sqlite_stmt_func>;

    unique_stmt_ptr put_stmt;
    unique_stmt_ptr put_update_stmt;
    unique_stmt_ptr get_stmt;
    unique_stmt_ptr erase_stmt;

    unique_stmt_ptr check_expire_stmt;
    unique_stmt_ptr expire_stmt;
    unique_stmt_ptr get_expiry_last_run_stmt;
    unique_stmt_ptr update_expiry_last_run_stmt;

    std::string full_path;
    std::string table_name;
    std::chrono::milliseconds pragma_timeout;
    std::chrono::milliseconds pragma_wait_on_busy;
};

} // namespace zeek::storage::backend::sqlite
