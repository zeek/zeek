// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/storage/Backend.h"

namespace zeek::storage::backends::sqlite {

class SQLite : public Backend {
public:
    SQLite() = default;
    ~SQLite() override = default;

    static Backend* Instantiate();

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return "SQLiteStorage"; }

    /**
     * Called by the manager system to open the backend.
     */
    bool DoOpen(RecordValPtr config, TypePtr vt) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    void Done() override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return db != nullptr; }

    /**
     * The workhorse method for Store().
     */
    BoolResult DoStore(ValPtr key, ValPtr value, bool overwrite = true) override;

    /**
     * The workhorse method for Retrieve().
     */
    ValResult DoRetrieve(ValPtr key) override;

    /**
     * The workhorse method for Retrieve().
     */
    BoolResult DoErase(ValPtr key) override;

private:
    bool checkError(int code);

    sqlite3* db = nullptr;
    std::string full_path;
    std::string table_name;
};

} // namespace zeek::storage::backends::sqlite
