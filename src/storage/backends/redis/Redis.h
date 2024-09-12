// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/storage/Backend.h"

struct redisContext;

namespace zeek::storage::backends::redis {

class RedisSync;
class RedisAsync;

class Redis : public Backend {
public:
    Redis() : Backend(true) {}
    ~Redis() override = default;

    static Backend* Instantiate();

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return "RedisStorage"; }

    /**
     * Called by the manager system to open the backend.
     */
    ErrorResult DoOpen(RecordValPtr config) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    void Done() override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override;

    /**
     * The workhorse method for Retrieve().
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

private:
    ErrorResult checkError(int code);

    RedisSync* sync = nullptr;
    RedisAsync* async = nullptr;

    std::string server_addr;
    std::string key_prefix;
};

} // namespace zeek::storage::backends::redis
