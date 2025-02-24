
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
    StorageDummy(std::string_view tag) : Backend(zeek::storage::SupportedModes::SYNC, tag) {}
    ~StorageDummy() override = default;

    static zeek::storage::BackendPtr Instantiate(std::string_view tag);

    /**
     * Called by the manager system to open the backend.
     */
    zeek::storage::OperationResult DoOpen(zeek::RecordValPtr options,
                                          zeek::storage::OpenResultCallback* cb = nullptr) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    zeek::storage::OperationResult DoClose(zeek::storage::OperationResultCallback* cb = nullptr) override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return open; }

    /**
     * The workhorse method for Put().
     */
    zeek::storage::OperationResult DoPut(zeek::ValPtr key, zeek::ValPtr value, bool overwrite = true,
                                         double expiration_time = 0,
                                         zeek::storage::OperationResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Get().
     */
    zeek::storage::OperationResult DoGet(zeek::ValPtr key,
                                         zeek::storage::OperationResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Erase().
     */
    zeek::storage::OperationResult DoErase(zeek::ValPtr key,
                                           zeek::storage::OperationResultCallback* cb = nullptr) override;

private:
    std::map<std::string, std::string> data;
    bool open = false;
};

} // namespace btest::storage::backend
