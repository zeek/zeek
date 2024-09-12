// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/storage/Backend.h"

struct redisContext;

namespace zeek::storage::backends::redis {

class RedisSync {
public:
    RedisSync(TypePtr val_type) : val_type(std::move(val_type)) {}

    /**
     * Called by the manager system to open the backend.
     */
    ErrorResult DoOpen(RecordValPtr config);

    /**
     * Finalizes the backend when it's being closed.
     */
    void Done();

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() { return ctx != nullptr; }

    /**
     * The workhorse method for Retrieve().
     */
    ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                      ErrorResultCallback* cb = nullptr);

    /**
     * The workhorse method for Get().
     */
    ValResult DoGet(ValPtr key, ValResultCallback* cb = nullptr);

    /**
     * The workhorse method for Erase().
     */
    ErrorResult DoErase(ValPtr key, ErrorResultCallback* cb = nullptr);

private:
    TypePtr val_type;

    redisContext* ctx = nullptr;

    std::string server_addr;
    std::string key_prefix;
};

} // namespace zeek::storage::backends::redis
