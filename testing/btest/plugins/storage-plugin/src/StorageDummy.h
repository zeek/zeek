
#pragma once

#include <map>
#include <string>

#include "zeek/storage/Backend.h"

namespace btest::storage::backend {

/**
 * A Foo reader to measure performance of the input framework.
 */
class StorageDummy : public zeek::storage::Backend {
public:
    StorageDummy() = default;
    ~StorageDummy() override = default;

    static zeek::storage::Backend* Instantiate();

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return "StorageDummy"; }

    /**
     * Called by the manager system to open the backend.
     */
    zeek::storage::ErrorResult DoOpen(zeek::RecordValPtr config) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    void Done() override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return open; }

    /**
     * The workhorse method for Put().
     */
    zeek::storage::ErrorResult DoPut(zeek::ValPtr key, zeek::ValPtr value, bool overwrite = true) override;

    /**
     * The workhorse method for Get().
     */
    zeek::storage::ValResult DoGet(zeek::ValPtr key, zeek::TypePtr vt) override;

    /**
     * The workhorse method for Erase().
     */
    zeek::storage::ErrorResult DoErase(zeek::ValPtr key) override;

private:
    std::map<std::string, std::string> data;
    bool open = false;
};

} // namespace btest::storage::backend
