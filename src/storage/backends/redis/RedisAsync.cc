// See the file "COPYING" in the main distribution directory for copyright.

#include "RedisAsync.h"

#include "zeek/Func.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"

#include "hiredis/async.h"
#include "hiredis/hiredis.h"

namespace {

class Tracer {
public:
    Tracer(const std::string& where) : where(where) { /*printf("%s\n", where.c_str());*/ }
    ~Tracer() { /* printf("%s done\n", where.c_str()); */ }
    std::string where;
};

void redisOnConnect(const redisAsyncContext* ctx, int status) {
    auto t = Tracer("connect");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(ctx->data);
    backend->OnConnect(status);
}

void redisOnDisconnect(const redisAsyncContext* ctx, int status) {
    auto t = Tracer("disconnect");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(ctx->data);
    backend->OnDisconnect(status);
}

void redisPut(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("put");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(ctx->data);
    auto callback = static_cast<zeek::storage::ErrorResultCallback*>(privdata);
    backend->HandlePutResult(static_cast<redisReply*>(reply), callback);
}

void redisGet(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("get");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(ctx->data);
    auto callback = static_cast<zeek::storage::ValResultCallback*>(privdata);
    backend->HandleGetResult(static_cast<redisReply*>(reply), callback);
}

void redisErase(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("erase");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(ctx->data);
    auto callback = static_cast<zeek::storage::ErrorResultCallback*>(privdata);
    backend->HandleEraseResult(static_cast<redisReply*>(reply), callback);
}

void redisAddRead(void* privdata) {
    auto t = Tracer("addread");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(privdata);
    backend->OnAddRead();
}
void redisDelRead(void* privdata) {
    auto t = Tracer("delread");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(privdata);
    backend->OnDelRead();
}
void redisAddWrite(void* privdata) {
    auto t = Tracer("addwrite");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(privdata);
    backend->OnAddWrite();
}
void redisDelWrite(void* privdata) {
    auto t = Tracer("delwrite");
    auto backend = static_cast<zeek::storage::backends::redis::RedisAsync*>(privdata);
    backend->OnDelWrite();
}

} // namespace

namespace zeek::storage::backends::redis {

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
ErrorResult RedisAsync::DoOpen(RecordValPtr config) {
    redisOptions opt = {0};

    StringValPtr address = config->GetField<StringVal>("server_addr");
    if ( address ) {
        PortValPtr port = config->GetField<PortVal>("server_port");
        server_addr = util::fmt("%s:%d", address->ToStdStringView().data(), port->Port());
        REDIS_OPTIONS_SET_TCP(&opt, address->ToStdStringView().data(), port->Port());
    }
    else {
        StringValPtr unix_sock = config->GetField<StringVal>("server_unix_socket");
        server_addr = address->ToStdString();
        REDIS_OPTIONS_SET_UNIX(&opt, unix_sock->ToStdStringView().data());
    }

    opt.options |= REDIS_OPT_PREFER_IPV4;
    opt.options |= REDIS_OPT_NOAUTOFREEREPLIES;

    struct timeval timeout = {5, 0};
    opt.connect_timeout = &timeout;

    ctx = redisAsyncConnectWithOptions(&opt);
    if ( ctx == nullptr || ctx->err ) {
        // This block doesn't necessarily mean the connection failed. It means
        // that hiredis failed to set up the async context. Connection failure
        // is returned later via the OnConnect callback.
        std::string errmsg = util::fmt("Failed to open connection to Redis server at %s", server_addr.c_str());
        if ( ctx ) {
            errmsg.append(": ");
            errmsg.append(ctx->errstr);
        }

        redisAsyncFree(ctx);
        ctx = nullptr;
        return errmsg;
    }

    // The context is passed to the handler methods. Setting this data object
    // pointer allows us to look up the backend in the handlers.
    ctx->data = this;
    ctx->ev.data = this;

    redisAsyncSetConnectCallback(ctx, redisOnConnect);
    redisAsyncSetDisconnectCallback(ctx, redisOnDisconnect);

    // These four callbacks handle the file descriptor coming and going for read
    // and write operations for hiredis. Their subsequent callbacks will
    // register/unregister with iosource_mgr as needed. I tried just registering
    // full time for both read and write but it leads to weird syncing issues
    // within the hiredis code. This is safer in regards to the library, even if
    // it results in waking up our IO loop more frequently.
    ctx->ev.addRead = redisAddRead;
    ctx->ev.delRead = redisDelRead;
    ctx->ev.addWrite = redisAddWrite;
    ctx->ev.delWrite = redisDelWrite;

    key_prefix = config->GetField<StringVal>("key_prefix")->ToStdString();

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void RedisAsync::Done() {
    if ( ctx ) {
        iosource_mgr->UnregisterFd(ctx->c.fd, this, IOSource::READ | IOSource::WRITE);
        redisAsyncDisconnect(ctx);
        redisAsyncFree(ctx);
        ctx = nullptr;
        connected = false;
    }
}

void RedisAsync::OnConnect(int status) {
    if ( status == REDIS_OK ) {
        connected = true;
        return;
    }

    // TODO: we could attempt to reconnect here
}

void RedisAsync::OnDisconnect(int status) {
    if ( status == REDIS_OK ) {
        // TODO: this was an intentional disconnect, nothing to do?
    }
    else {
        // TODO: this was unintentional, should we reconnect?
    }

    connected = false;
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult RedisAsync::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time,
                              ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    std::string format = "SET %s:%s %s";
    if ( ! overwrite )
        format.append(" NX");
    if ( expiration_time > 0.0 )
        format.append(" PXAT %d");

    auto json_key = key->ToJSON()->ToStdString();
    auto json_value = value->ToJSON()->ToStdString();

    int status;
    if ( expiration_time > 0.0 )
        status = redisAsyncCommand(ctx, redisPut, cb, format.c_str(), key_prefix.data(), json_key.data(),
                                   json_value.data(), static_cast<uint64_t>(expiration_time * 1e6));
    else
        status =
            redisAsyncCommand(ctx, redisPut, cb, format.c_str(), key_prefix.data(), json_key.data(), json_value.data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Failed to queue async put operation: %s", ctx->errstr);

    return std::nullopt;
}

void RedisAsync::HandlePutResult(redisReply* reply, ErrorResultCallback* callback) {
    ErrorResult res;
    if ( ! connected )
        res = util::fmt("Connection is not open");
    else if ( reply && reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Async put operation failed: %s", reply->str);

    freeReplyObject(reply);

    callback->Complete(res);
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult RedisAsync::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( ! ctx )
        return nonstd::unexpected<std::string>("Connection is not open");

    int status =
        redisAsyncCommand(ctx, redisGet, cb, "GET %s:%s", key_prefix.data(), key->ToJSON()->ToStdStringView().data());

    if ( connected && status == REDIS_ERR )
        return nonstd::unexpected<std::string>(util::fmt("Failed to queue async get operation: %s", ctx->errstr));

    return nonstd::unexpected<std::string>("Async get operation completed successfully");
}

void RedisAsync::HandleGetResult(redisReply* reply, ValResultCallback* callback) {
    ValResult res;
    if ( ! connected )
        res = nonstd::unexpected<std::string>("Connection is not open");
    else {
        auto val = zeek::detail::ValFromJSON(reply->str, val_type, Func::nil);
        freeReplyObject(reply);

        if ( std::holds_alternative<ValPtr>(val) ) {
            ValPtr val_v = std::get<ValPtr>(val);
            res = val_v;
        }

        if ( ! res )
            res = nonstd::unexpected<std::string>(std::get<std::string>(val));
    }

    callback->Complete(res);
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult RedisAsync::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    auto json_key = key->ToJSON();

    int status =
        redisAsyncCommand(ctx, redisErase, cb, "DEL %s:%s", key_prefix.data(), json_key->ToStdStringView().data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Failed to queue async erase operation failed: %s", ctx->errstr);

    return std::nullopt;
}

void RedisAsync::HandleEraseResult(redisReply* reply, ErrorResultCallback* callback) {
    ErrorResult res;
    if ( ! connected )
        res = "Connection is not open";
    else if ( reply && reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Async erase operation failed: %s", reply->str);

    freeReplyObject(reply);

    callback->Complete(res);
}

void RedisAsync::ProcessFd(int fd, int flags) {
    if ( (flags & IOSource::ProcessFlags::READ) != 0 )
        redisAsyncHandleRead(ctx);
    if ( (flags & IOSource::ProcessFlags::WRITE) != 0 )
        redisAsyncHandleWrite(ctx);
}

void RedisAsync::OnAddRead() {
    if ( ! ctx )
        return;

    iosource_mgr->RegisterFd(ctx->c.fd, this, IOSource::READ);
}
void RedisAsync::OnDelRead() {
    if ( ! ctx )
        return;

    iosource_mgr->UnregisterFd(ctx->c.fd, this, IOSource::READ);
}
void RedisAsync::OnAddWrite() {
    if ( ! ctx )
        return;

    iosource_mgr->RegisterFd(ctx->c.fd, this, IOSource::WRITE);
}
void RedisAsync::OnDelWrite() {
    if ( ! ctx )
        return;

    iosource_mgr->UnregisterFd(ctx->c.fd, this, IOSource::WRITE);
}

} // namespace zeek::storage::backends::redis
