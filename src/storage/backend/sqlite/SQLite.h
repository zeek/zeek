// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/storage/Backend.h"

// Forward declare these to avoid including sqlite3.h here
struct sqlite3;
struct sqlite3_stmt;

namespace zeek::storage::backend::sqlite {

class SQLite : public Backend {
public:
    SQLite(std::string_view tag) : Backend(false, tag) {}
    ~SQLite() override = default;

    static BackendPtr Instantiate(std::string_view tag);

    /**
     * Called by the manager system to open the backend.
     */
    ErrorResult DoOpen(RecordValPtr options) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    void Close() override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return db != nullptr; }

    /**
     * The workhorse method for Put().
     */
    ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                      ErrorResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Get().
     */
    ValResult DoGet(ValPtr key, ValResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Erase().
     */
    ErrorResult DoErase(ValPtr key, ErrorResultCallback* cb = nullptr) override;

    // TODO: add support for checking for expired data

private:
    ErrorResult checkError(int code);

    sqlite3* db = nullptr;
    std::string full_path;
    std::string table_name;
};

} // namespace zeek::storage::backend::sqlite
