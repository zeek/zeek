// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/IOSource.h"
#include "zeek/storage/Backend.h"

// Forward declare some types from hiredis to avoid including the header
struct redisAsyncContext;
struct redisReply;
struct redisPollEvents;

namespace zeek::storage::backend::redis {
class Redis : public Backend, public iosource::IOSource {
public:
    Redis(std::string_view tag) : Backend(true, tag), IOSource(true) {}
    ~Redis() override = default;

    static BackendPtr Instantiate(std::string_view tag);

    /**
     * Returns a descriptive tag representing the source for debugging.
     * This has to be overloaded for Redis because IOSource requires it.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return tag.c_str(); }

    /**
     * Called by the manager system to open the backend.
     */
    ErrorResult DoOpen(RecordValPtr options, OpenResultCallback* cb = nullptr) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    ErrorResult DoClose(ErrorResultCallback* cb = nullptr) override;

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

    void HandlePutResult(redisReply* reply, ErrorResultCallback* callback);
    void HandleGetResult(redisReply* reply, ValResultCallback* callback);
    void HandleEraseResult(redisReply* reply, ErrorResultCallback* callback);
    void HandleZRANGEBYSCORE(redisReply* reply);

    // HandleGeneric exists so that async-running-as-sync operations can remove
    // themselves from the list of active operations.
    void HandleGeneric() { --active_ops; }

private:
    ValResult ParseGetReply(redisReply* reply) const;
    void Poll();

    redisAsyncContext* async_ctx = nullptr;

    // When running in sync mode, this is used to keep a queue of replies as
    // responses come in from the remote calls until we run out of data to
    // poll.
    std::deque<redisReply*> reply_queue;

    std::string server_addr;
    std::string key_prefix;
    std::atomic<bool> connected = false;
    int active_ops = 0;
};

} // namespace zeek::storage::backend::redis
