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
     * Called by the manager system to open the backend.
     */
    OperationResult DoOpen(RecordValPtr options, OpenResultCallback* cb = nullptr) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    OperationResult DoClose(OperationResultCallback* cb = nullptr) override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return db != nullptr; }

    /**
     * The workhorse method for Put().
     */
    OperationResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                          OperationResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Get().
     */
    OperationResult DoGet(ValPtr key, OperationResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Erase().
     */
    OperationResult DoErase(ValPtr key, OperationResultCallback* cb = nullptr) override;

    /**
     * Removes any entries in the backend that have expired. Can be overridden by
     * derived classes.
     */
    void Expire() override;

private:
    OperationResult CheckError(int code);
    OperationResult Step(sqlite3_stmt* stmt, bool parse_value = false);

    sqlite3* db = nullptr;
    std::unordered_map<std::string, sqlite3_stmt*> prepared_stmts;

    std::string full_path;
    std::string table_name;
};

} // namespace zeek::storage::backend::sqlite
