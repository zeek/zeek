// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/redis/Redis.h"

#include "zeek/Func.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"

#include "hiredis/async.h"
#include "hiredis/hiredis.h"

// Anonymous callback handler methods for the hiredis async API.
namespace {

class Tracer {
public:
    Tracer(const std::string& where) : where(where) { /*printf("%s\n", where.c_str());*/ }
    ~Tracer() { /* printf("%s done\n", where.c_str()); */ }
    std::string where;
};

void redisOnConnect(const redisAsyncContext* ctx, int status) {
    auto t = Tracer("connect");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->OnConnect(status);
}

void redisOnDisconnect(const redisAsyncContext* ctx, int status) {
    auto t = Tracer("disconnect");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->OnDisconnect(status);
}

void redisPut(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("put");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    auto callback = static_cast<zeek::storage::ErrorResultCallback*>(privdata);
    backend->HandlePutResult(static_cast<redisReply*>(reply), callback);
}

void redisGet(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("get");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    auto callback = static_cast<zeek::storage::ValResultCallback*>(privdata);
    backend->HandleGetResult(static_cast<redisReply*>(reply), callback);
}

void redisErase(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("erase");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    auto callback = static_cast<zeek::storage::ErrorResultCallback*>(privdata);
    backend->HandleEraseResult(static_cast<redisReply*>(reply), callback);
}

void redisAddRead(void* privdata) {
    auto t = Tracer("addread");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(privdata);
    backend->OnAddRead();
}
void redisDelRead(void* privdata) {
    auto t = Tracer("delread");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(privdata);
    backend->OnDelRead();
}
void redisAddWrite(void* privdata) {
    auto t = Tracer("addwrite");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(privdata);
    backend->OnAddWrite();
}
void redisDelWrite(void* privdata) {
    auto t = Tracer("delwrite");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(privdata);
    backend->OnDelWrite();
}

} // namespace

namespace zeek::storage::backend::redis {

storage::BackendPtr Redis::Instantiate(std::string_view tag) { return make_intrusive<Redis>(tag); }

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
ErrorResult Redis::DoOpen(RecordValPtr options) {
    // When reading traces we disable storage async mode globally (see src/storage/Backend.cc) since
    // time moves forward based on the pcap and not based on real time.
    async_mode = options->GetField<BoolVal>("async_mode")->Get() && ! zeek::run_state::reading_traces;
    key_prefix = options->GetField<StringVal>("key_prefix")->ToStdString();

    redisOptions opt = {0};

    StringValPtr host = options->GetField<StringVal>("server_host");
    if ( host ) {
        PortValPtr port = options->GetField<PortVal>("server_port");
        server_addr = util::fmt("%s:%d", host->ToStdStringView().data(), port->Port());
        REDIS_OPTIONS_SET_TCP(&opt, host->ToStdStringView().data(), port->Port());
    }
    else {
        StringValPtr unix_sock = options->GetField<StringVal>("server_unix_socket");
        if ( ! unix_sock )
            return util::fmt(
                "Either server_host/server_port or server_unix_socket must be set in Redis options record");

        server_addr = unix_sock->ToStdString();
        REDIS_OPTIONS_SET_UNIX(&opt, server_addr.c_str());
    }

    opt.options |= REDIS_OPT_PREFER_IPV4;
    opt.options |= REDIS_OPT_NOAUTOFREEREPLIES;

    struct timeval timeout = {5, 0};
    opt.connect_timeout = &timeout;

    if ( async_mode ) {
        async_ctx = redisAsyncConnectWithOptions(&opt);
        if ( async_ctx == nullptr || async_ctx->err ) {
            // This block doesn't necessarily mean the connection failed. It means
            // that hiredis failed to set up the async context. Connection failure
            // is returned later via the OnConnect callback.
            std::string errmsg = util::fmt("Failed to open connection to Redis server at %s", server_addr.c_str());
            if ( async_ctx ) {
                errmsg.append(": ");
                errmsg.append(async_ctx->errstr);
            }

            redisAsyncFree(async_ctx);
            async_ctx = nullptr;
            return errmsg;
        }

        // The context is passed to the handler methods. Setting this data object
        // pointer allows us to look up the backend in the handlers.
        async_ctx->data = this;
        async_ctx->ev.data = this;

        redisAsyncSetConnectCallback(async_ctx, redisOnConnect);
        redisAsyncSetDisconnectCallback(async_ctx, redisOnDisconnect);

        // These four callbacks handle the file descriptor coming and going for read
        // and write operations for hiredis. Their subsequent callbacks will
        // register/unregister with iosource_mgr as needed. I tried just registering
        // full time for both read and write but it leads to weird syncing issues
        // within the hiredis code. This is safer in regards to the library, even if
        // it results in waking up our IO loop more frequently.
        async_ctx->ev.addRead = redisAddRead;
        async_ctx->ev.delRead = redisDelRead;
        async_ctx->ev.addWrite = redisAddWrite;
        async_ctx->ev.delWrite = redisDelWrite;
    }
    else {
        ctx = redisConnectWithOptions(&opt);
        if ( ctx == nullptr || ctx->err ) {
            if ( ctx )
                return util::fmt("Failed to open connection to Redis server at %s", server_addr.c_str());
            else
                return util::fmt("Failed to open connection to Redis server at %s: %s", server_addr.c_str(),
                                 ctx->errstr);
        }

        connected = true;
    }

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void Redis::Close() {
    connected = false;

    if ( async_mode ) {
        // This will probably result in an error since hiredis should have
        // already removed the file descriptor via the delRead and delWrite
        // callbacks, but do it anyways just to be sure.
        iosource_mgr->UnregisterFd(async_ctx->c.fd, this, IOSource::READ | IOSource::WRITE);
        redisAsyncDisconnect(async_ctx);
        redisAsyncFree(async_ctx);
        async_ctx = nullptr;
    }
    else {
        redisFree(ctx);
        ctx = nullptr;
    }
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult Redis::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    // The async context will queue operations until it's connected fully.
    if ( ! connected && ! async_ctx )
        return "Connection is not open";

    std::string format = "SET %s:%s %s";
    if ( ! overwrite )
        format.append(" NX");

    // Use built-in expiration if reading live data, since time will move
    // forward consistently.  If reading pcaps, we'll do something else.
    if ( expiration_time > 0.0 && ! zeek::run_state::reading_traces )
        format.append(" PXAT %d");

    double expire_time = expiration_time + run_state::network_time;

    auto json_key = key->ToJSON()->ToStdString();
    auto json_value = value->ToJSON()->ToStdString();

    if ( async_mode ) {
        int status;
        if ( expiration_time > 0.0 && ! zeek::run_state::reading_traces )
            status = redisAsyncCommand(async_ctx, redisPut, cb, format.c_str(), key_prefix.data(), json_key.data(),
                                       json_value.data(), static_cast<uint64_t>(expire_time * 1e6));
        else
            status = redisAsyncCommand(async_ctx, redisPut, cb, format.c_str(), key_prefix.data(), json_key.data(),
                                       json_value.data());

        if ( connected && status == REDIS_ERR )
            return util::fmt("Failed to queue async put operation: %s", async_ctx->errstr);
    }
    else {
        redisReply* reply;
        if ( expiration_time > 0.0 && ! zeek::run_state::reading_traces )
            reply = (redisReply*)redisCommand(ctx, format.c_str(), key_prefix.data(), json_key.data(),
                                              json_value.data(), static_cast<uint64_t>(expire_time * 1e6));
        else
            reply =
                (redisReply*)redisCommand(ctx, format.c_str(), key_prefix.data(), json_key.data(), json_value.data());

        if ( ! reply )
            return util::fmt("Put operation failed: %s", ctx->errstr);

        freeReplyObject(reply);
    }

    return std::nullopt;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult Redis::DoGet(ValPtr key, ValResultCallback* cb) {
    // The async context will queue operations until it's connected fully.
    if ( ! connected && ! async_ctx )
        return zeek::unexpected<std::string>("Connection is not open");

    if ( async_mode ) {
        int status = redisAsyncCommand(async_ctx, redisGet, cb, "GET %s:%s", key_prefix.data(),
                                       key->ToJSON()->ToStdStringView().data());

        if ( connected && status == REDIS_ERR )
            return zeek::unexpected<std::string>(
                util::fmt("Failed to queue async get operation: %s", async_ctx->errstr));

        // There isn't a result to return here. That happens in HandleGetResult.
        return zeek::unexpected<std::string>("");
    }
    else {
        auto reply =
            (redisReply*)redisCommand(ctx, "GET %s:%s", key_prefix.data(), key->ToJSON()->ToStdStringView().data());

        if ( ! reply )
            return zeek::unexpected<std::string>(util::fmt("Get operation failed: %s", ctx->errstr));

        return ParseGetReply(reply);
    }
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult Redis::DoErase(ValPtr key, ErrorResultCallback* cb) {
    // The async context will queue operations until it's connected fully.
    if ( ! connected && ! async_ctx )
        return "Connection is not open";

    if ( async_mode ) {
        int status = redisAsyncCommand(async_ctx, redisErase, cb, "DEL %s:%s", key_prefix.data(),
                                       key->ToJSON()->ToStdStringView().data());

        if ( connected && status == REDIS_ERR )
            return util::fmt("Failed to queue async erase operation failed: %s", async_ctx->errstr);
    }
    else {
        redisReply* reply =
            (redisReply*)redisCommand(ctx, "DEL %s:%s", key_prefix.data(), key->ToJSON()->ToStdStringView().data());

        if ( ! reply )
            return util::fmt("Put operation failed: %s", ctx->errstr);

        freeReplyObject(reply);
    }

    return std::nullopt;
}

void Redis::HandlePutResult(redisReply* reply, ErrorResultCallback* callback) {
    ErrorResult res;
    if ( ! connected )
        res = util::fmt("Connection is not open");
    else if ( ! reply )
        res = util::fmt("Async put operation returned null reply");
    else if ( reply && reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Async put operation failed: %s", reply->str);

    freeReplyObject(reply);
    callback->Complete(res);
    delete callback;
}

void Redis::HandleGetResult(redisReply* reply, ValResultCallback* callback) {
    ValResult res;
    if ( ! connected )
        res = zeek::unexpected<std::string>("Connection is not open");
    else
        res = ParseGetReply(reply);

    callback->Complete(res);
    delete callback;
}

void Redis::HandleEraseResult(redisReply* reply, ErrorResultCallback* callback) {
    ErrorResult res;
    if ( ! connected )
        res = "Connection is not open";
    else if ( ! reply )
        res = util::fmt("Async erase operation returned null reply");
    else if ( reply && reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Async erase operation failed: %s", reply->str);

    freeReplyObject(reply);

    callback->Complete(res);
    delete callback;
}

void Redis::OnConnect(int status) {
    if ( status == REDIS_OK ) {
        connected = true;
        return;
    }

    // TODO: we could attempt to reconnect here
}

void Redis::OnDisconnect(int status) {
    if ( status == REDIS_OK ) {
        // TODO: this was an intentional disconnect, nothing to do?
    }
    else {
        // TODO: this was unintentional, should we reconnect?
    }

    connected = false;
}

void Redis::OnAddRead() {
    if ( ! async_ctx )
        return;

    iosource_mgr->RegisterFd(async_ctx->c.fd, this, IOSource::READ);
}
void Redis::OnDelRead() {
    if ( ! async_ctx )
        return;

    iosource_mgr->UnregisterFd(async_ctx->c.fd, this, IOSource::READ);
}
void Redis::OnAddWrite() {
    if ( ! async_ctx )
        return;

    iosource_mgr->RegisterFd(async_ctx->c.fd, this, IOSource::WRITE);
}
void Redis::OnDelWrite() {
    if ( ! async_ctx )
        return;

    iosource_mgr->UnregisterFd(async_ctx->c.fd, this, IOSource::WRITE);
}

void Redis::ProcessFd(int fd, int flags) {
    if ( (flags & IOSource::ProcessFlags::READ) != 0 )
        redisAsyncHandleRead(async_ctx);
    if ( (flags & IOSource::ProcessFlags::WRITE) != 0 )
        redisAsyncHandleWrite(async_ctx);
}

ValResult Redis::ParseGetReply(redisReply* reply) const {
    ValResult res;

    if ( ! reply )
        res = zeek::unexpected<std::string>("GET returned null reply");
    else if ( ! reply->str )
        res = zeek::unexpected<std::string>("GET returned key didn't exist");
    else {
        auto val = zeek::detail::ValFromJSON(reply->str, val_type, Func::nil);
        if ( std::holds_alternative<ValPtr>(val) )
            res = std::get<ValPtr>(val);
        else
            res = zeek::unexpected<std::string>(std::get<std::string>(val));
    }

    freeReplyObject(reply);
    return res;
}

} // namespace zeek::storage::backend::redis
