// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/storage/Backend.h"

// Forward declare these to avoid including sqlite3.h here
struct sqlite3;
struct sqlite3_stmt;

namespace zeek::storage::backend::sqlite {

class SQLite : public Backend {
public:
    SQLite(std::string_view tag) : Backend(SupportedModes::SYNC, tag) {}
    ~SQLite() override = default;

    static BackendPtr Instantiate(std::string_view tag);

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return db != nullptr; }

private:
    OperationResult DoOpen(RecordValPtr options, OpenResultCallback* cb = nullptr) override;
    OperationResult DoClose(OperationResultCallback* cb = nullptr) override;
    OperationResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                          OperationResultCallback* cb = nullptr) override;
    OperationResult DoGet(ValPtr key, OperationResultCallback* cb = nullptr) override;
    OperationResult DoErase(ValPtr key, OperationResultCallback* cb = nullptr) override;
    void DoExpire() override;

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
    OperationResult Step(sqlite3_stmt* stmt, bool parse_value = false);

    sqlite3* db = nullptr;

    using stmt_deleter = std::function<void(sqlite3_stmt*)>;
    using unique_stmt_ptr = std::unique_ptr<sqlite3_stmt, stmt_deleter>;
    unique_stmt_ptr put_stmt;
    unique_stmt_ptr put_update_stmt;
    unique_stmt_ptr get_stmt;
    unique_stmt_ptr erase_stmt;
    unique_stmt_ptr expire_stmt;

    std::string full_path;
    std::string table_name;
};

} // namespace zeek::storage::backend::sqlite
