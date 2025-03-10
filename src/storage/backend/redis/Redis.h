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

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return connected; }

    bool ExpireRunning() const { return expire_running.load(); }

private:
    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(OperationResultCallback* cb) override;
    OperationResult DoPut(OperationResultCallback* cb, ValPtr key, ValPtr value, bool overwrite = true,
                          double expiration_time = 0) override;
    OperationResult DoGet(OperationResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(OperationResultCallback* cb, ValPtr key) override;
    void DoExpire(double current_network_time) override;
    void DoPoll() override;

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
    std::atomic<bool> expire_running = false;
    std::atomic<int> active_ops = 0;
};

} // namespace zeek::storage::backend::redis
