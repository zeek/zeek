// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <mutex>

#include "zeek/iosource/IOSource.h"
#include "zeek/storage/Backend.h"

// Forward declare some types from hiredis to avoid including the header
struct redisAsyncContext;
struct redisReply;
struct redisPollEvents;

namespace zeek::storage::backend::redis {
class Redis : public Backend, public iosource::IOSource {
public:
    Redis(std::string_view tag) : Backend(SupportedModes::ASYNC, tag), IOSource(true) {}
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
    OperationResult DoOpen(RecordValPtr options, OpenResultCallback* cb = nullptr) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    OperationResult DoClose(OperationResultCallback* cb = nullptr) override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return connected; }

    /**
     * The workhorse method for Retrieve().
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

    // IOSource interface
    double GetNextTimeout() override { return -1; }
    void Process() override {}
    void ProcessFd(int fd, int flags) override;

    // Hiredis async interface
    void OnConnect(int status);
    void OnDisconnect(int status);

    void HandlePutResult(redisReply* reply, OperationResultCallback* callback);
    void HandleGetResult(redisReply* reply, OperationResultCallback* callback);
    void HandleEraseResult(redisReply* reply, OperationResultCallback* callback);
    void HandleGeneric(redisReply* reply);

protected:
    void Poll() override;

private:
    OperationResult ParseGetReply(redisReply* reply) const;

    redisAsyncContext* async_ctx = nullptr;

    // When running in sync mode, this is used to keep a queue of replies as
    // responses come in from the remote calls until we run out of data to
    // poll.
    std::deque<redisReply*> reply_queue;

    OpenResultCallback* open_cb;
    std::mutex expire_mutex;

    std::string server_addr;
    std::string key_prefix;
    std::atomic<bool> connected = false;
    int active_ops = 0;
};

} // namespace zeek::storage::backend::redis
