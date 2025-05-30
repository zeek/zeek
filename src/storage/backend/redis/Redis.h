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
class Redis final : public Backend, public iosource::IOSource {
public:
    Redis() : Backend(SupportedModes::ASYNC, "REDIS"), IOSource(true) {}
    ~Redis() override = default;

    static BackendPtr Instantiate();

    /**
     * Returns a descriptive tag representing the source for debugging.
     * This has to be overloaded for Redis because IOSource requires it.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return tag_str.c_str(); }

    // IOSource interface
    double GetNextTimeout() override { return -1; }
    void Process() override {}
    void ProcessFd(int fd, int flags) override;

    // Hiredis async interface
    void OnConnect(int status);
    void OnDisconnect(int status);

    void HandlePutResult(redisReply* reply, ResultCallback* callback);
    void HandleGetResult(redisReply* reply, ResultCallback* callback);
    void HandleEraseResult(redisReply* reply, ResultCallback* callback);
    void HandleGeneric(redisReply* reply);
    void HandleInfoResult(redisReply* reply);

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override { return connected; }

    bool ExpireRunning() const { return expire_running.load(); }

private:
    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(ResultCallback* cb) override;
    OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                          double expiration_time) override;
    OperationResult DoGet(ResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(ResultCallback* cb, ValPtr key) override;
    void DoExpire(double current_network_time) override;
    void DoPoll() override;

    OperationResult ParseReplyError(std::string_view op_str, std::string_view reply_err_str) const;
    OperationResult CheckServerVersion();

    redisAsyncContext* async_ctx = nullptr;

    // When running in sync mode, this is used to keep a queue of replies as
    // responses come in from the remote calls until we run out of data to
    // poll.
    std::deque<redisReply*> reply_queue;

    OpenResultCallback* open_cb = nullptr;
    ResultCallback* close_cb = nullptr;
    std::mutex expire_mutex;

    std::string server_addr;
    std::string key_prefix;
    std::string disconnect_reason;

    std::atomic<bool> connected = false;
    std::atomic<bool> expire_running = false;
    std::atomic<int> active_ops = 0;
};

} // namespace zeek::storage::backend::redis
