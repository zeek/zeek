// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/IOSource.h"
#include "zeek/storage/Backend.h"

// Forward declare some types from hiredis to avoid including the header
struct redisContext;
struct redisAsyncContext;
struct redisReply;

namespace zeek::storage::backends::redis {

class Redis : public Backend, public iosource::IOSource {
public:
    Redis() : Backend(true), IOSource(true) {}
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
    bool IsOpen() override { return connected; }

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

    /**
     * Removes any entries in the backend that have expired. Can be overridden by
     * derived classes.
     */
    void Expire() override;

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
    ValResult ParseGetReply(redisReply* reply) const;

    redisContext* ctx = nullptr;
    redisAsyncContext* async_ctx = nullptr;
    bool connected = true;

    std::string server_addr;
    std::string key_prefix;
    bool async_mode = false;
};

} // namespace zeek::storage::backends::redis
