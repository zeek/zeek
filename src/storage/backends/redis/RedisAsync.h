// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/IOSource.h"
#include "zeek/storage/Backend.h"

// Forward declare some types from hiredis to avoid including the header here
struct redisAsyncContext;
struct redisReply;

namespace zeek::storage::backends::redis {

class RedisAsync : public zeek::iosource::IOSource {
public:
    RedisAsync(TypePtr val_type) : IOSource(true), val_type(std::move(val_type)) {}
    ~RedisAsync() override = default;

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return "RedisAsyncStorage"; }

    /**
     * Called by the manager system to open the backend.
     */
    ErrorResult DoOpen(RecordValPtr config);

    /**
     * Finalizes the backend when it's being closed.
     */
    void Done() override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() {
        // This can't just check the context because we might be in an in-between
        // state where the context is valid but we're not actually connected.
        return connected;
    }

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

    // IOSource interface
    double GetNextTimeout() override { return -1; }
    void Process() override {}
    void ProcessFd(int fd, int flags) override;

    // Hiredis async interface
    void OnConnect(int status);
    void OnDisconnect(int status);

    void OnAddRead();
    void OnDelRead();
    void OnAddWrite();
    void OnDelWrite();

    void HandlePutResult(redisReply* reply, ErrorResultCallback* callback);
    void HandleGetResult(redisReply* reply, ValResultCallback* callback);
    void HandleEraseResult(redisReply* reply, ErrorResultCallback* callback);

private:
    TypePtr val_type;

    redisAsyncContext* ctx = nullptr;
    bool connected = false;

    // Options passed in the record from script land
    std::string server_addr;
    std::string key_prefix;
};

} // namespace zeek::storage::backends::redis
