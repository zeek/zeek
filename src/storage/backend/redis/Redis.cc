// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/redis/Redis.h"

#include "zeek/DebugLogger.h"
#include "zeek/Func.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"

#include "hiredis/adapters/poll.h"
#include "hiredis/async.h"
#include "hiredis/hiredis.h"

// Anonymous callback handler methods for the hiredis async API.
namespace {

class Tracer {
public:
    Tracer(const std::string& where) : where(where) { // printf("%s\n", where.c_str());
    }
    ~Tracer() { // printf("%s done\n", where.c_str());
    }
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

void redisZRANGEBYSCORE(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("erase");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->HandleZRANGEBYSCORE(static_cast<redisReply*>(reply));
}

void redisGeneric(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("generic");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->HandleGeneric();
    freeReplyObject(reply);
}

// Because we called redisPollAttach in DoOpen(), privdata here is a
// redisPollEvents object. We can go through that object to get the context's
// data, which contains the backend. Because we overrode these callbacks in
// DoOpen, we still want to mimic their callbacks to redisPollTick functions
// correctly.
void redisAddRead(void* privdata) {
    auto t = Tracer("addread");
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->reading == 0 )
        zeek::iosource_mgr->RegisterFd(rpe->fd, backend, zeek::iosource::IOSource::READ);
    rpe->reading = 1;
}

void redisDelRead(void* privdata) {
    auto t = Tracer("delread");
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->reading == 1 )
        zeek::iosource_mgr->UnregisterFd(rpe->fd, backend, zeek::iosource::IOSource::READ);
    rpe->reading = 0;
}

void redisAddWrite(void* privdata) {
    auto t = Tracer("addwrite");
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->writing == 0 )
        zeek::iosource_mgr->RegisterFd(rpe->fd, backend, zeek::iosource::IOSource::WRITE);
    rpe->writing = 1;
}

void redisDelWrite(void* privdata) {
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto t = Tracer("delwrite");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->writing == 1 )
        zeek::iosource_mgr->UnregisterFd(rpe->fd, backend, zeek::iosource::IOSource::WRITE);
    rpe->writing = 0;
}

} // namespace

namespace zeek::storage::backend::redis {

storage::BackendPtr Redis::Instantiate(std::string_view tag) { return make_intrusive<Redis>(tag); }

/**
 * Called by the manager system to open the backend.
 */
ErrorResult Redis::DoOpen(RecordValPtr options, OpenResultCallback* cb) {
    RecordValPtr backend_options = options->GetField<RecordVal>("redis");

    key_prefix = backend_options->GetField<StringVal>("key_prefix")->ToStdString();

    redisOptions opt = {0};

    StringValPtr host = backend_options->GetField<StringVal>("server_host");
    if ( host ) {
        PortValPtr port = backend_options->GetField<PortVal>("server_port");
        server_addr = util::fmt("%s:%d", host->ToStdStringView().data(), port->Port());
        REDIS_OPTIONS_SET_TCP(&opt, host->ToStdStringView().data(), port->Port());
    }
    else {
        StringValPtr unix_sock = backend_options->GetField<StringVal>("server_unix_socket");
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

    ++active_ops;

    // TODO: Sort out how to pass the zeek callbacks for both open/done to the async
    // callbacks from hiredis so they can return errors.

    // The context is passed to the handler methods. Setting this data object
    // pointer allows us to look up the backend in the handlers.
    async_ctx->data = this;

    redisPollAttach(async_ctx);
    redisAsyncSetConnectCallback(async_ctx, redisOnConnect);
    redisAsyncSetDisconnectCallback(async_ctx, redisOnDisconnect);

    // redisAsyncSetConnectCallback sets the flag in the redisPollEvent for writing
    // so we can add this to our loop as well.
    zeek::iosource_mgr->RegisterFd(async_ctx->c.fd, this, zeek::iosource::IOSource::WRITE);

    // These four callbacks handle the file descriptor coming and going for read
    // and write operations for hiredis. Their subsequent callbacks will
    // register/unregister with iosource_mgr as needed. I tried just registering
    // full time for both read and write but it leads to weird syncing issues
    // within the hiredis code. This is safer in regards to the library, even if
    // it results in waking up our IO loop more frequently.
    //
    // redisPollAttach sets these to functions internal to the poll attachment,
    // but we override them for our own uses. See the callbacks for more info
    // about why.
    async_ctx->ev.addRead = redisAddRead;
    async_ctx->ev.delRead = redisDelRead;
    async_ctx->ev.addWrite = redisAddWrite;
    async_ctx->ev.delWrite = redisDelWrite;

    if ( ! cb )
        // Polling here will eventually call OnConnect, which will set the flag
        // that we're connected.
        Poll();

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
ErrorResult Redis::DoClose(ErrorResultCallback* cb) {
    connected = false;

    redisAsyncDisconnect(async_ctx);
    ++active_ops;

    if ( ! cb && ! zeek::run_state::terminating ) {
        Poll();
        // TODO: handle response
    }

    redisAsyncFree(async_ctx);
    async_ctx = nullptr;

    return std::nullopt;
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

    auto json_key = key->ToJSON()->ToStdString();
    auto json_value = value->ToJSON()->ToStdString();

    int status;
    // Use built-in expiration if reading live data, since time will move
    // forward consistently. If reading pcaps, we'll do something else.
    if ( expiration_time > 0.0 && ! zeek::run_state::reading_traces ) {
        format.append(" PXAT %d");
        status = redisAsyncCommand(async_ctx, redisPut, cb, format.c_str(), key_prefix.data(), json_key.data(),
                                   json_value.data(), static_cast<uint64_t>(expiration_time * 1e6));
    }
    else
        status = redisAsyncCommand(async_ctx, redisPut, cb, format.c_str(), key_prefix.data(), json_key.data(),
                                   json_value.data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Failed to queue put operation: %s", async_ctx->errstr);

    ++active_ops;

    if ( ! cb ) {
        Poll();

        redisReply* reply = reply_queue.front();
        reply_queue.pop_front();

        ErrorResult res;
        if ( ! connected )
            res = util::fmt("Connection is not open");
        else if ( ! reply )
            res = util::fmt("Async put operation returned null reply");
        else if ( reply && reply->type == REDIS_REPLY_ERROR )
            res = util::fmt("Async put operation failed: %s", reply->str);

        freeReplyObject(reply);
        if ( res.has_value() )
            return res;
    }

    // If reading pcaps insert into a secondary set that's ordered by expiration
    // time that gets checked by Expire().
    if ( expiration_time > 0.0 && zeek::run_state::reading_traces ) {
        format = "ZADD %s_expire";
        if ( ! overwrite )
            format.append(" NX");
        format += " %f %s";

        status = redisAsyncCommand(async_ctx, redisGeneric, NULL, format.c_str(), key_prefix.data(), expiration_time,
                                   json_key.data());
        if ( connected && status == REDIS_ERR )
            return util::fmt("ZADD operation failed: %s", async_ctx->errstr);

        ++active_ops;
    }

    if ( ! cb ) {
        // We don't care about the result from the ZADD, just that we wait
        // for it to finish.
        Poll();
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

    int status = redisAsyncCommand(async_ctx, redisGet, cb, "GET %s:%s", key_prefix.data(),
                                   key->ToJSON()->ToStdStringView().data());

    if ( connected && status == REDIS_ERR )
        return zeek::unexpected<std::string>(util::fmt("Failed to queue get operation: %s", async_ctx->errstr));

    ++active_ops;

    if ( ! cb ) {
        Poll();
        redisReply* reply = reply_queue.front();
        reply_queue.pop_front();

        auto res = ParseGetReply(reply);
        freeReplyObject(reply);
        return res;
    }

    // There isn't a result to return here. That happens in HandleGetResult for
    // async operations.
    return zeek::unexpected<std::string>("");
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult Redis::DoErase(ValPtr key, ErrorResultCallback* cb) {
    // The async context will queue operations until it's connected fully.
    if ( ! connected && ! async_ctx )
        return "Connection is not open";

    int status = redisAsyncCommand(async_ctx, redisErase, cb, "DEL %s:%s", key_prefix.data(),
                                   key->ToJSON()->ToStdStringView().data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Failed to queue erase operation failed: %s", async_ctx->errstr);

    ++active_ops;

    if ( ! cb ) {
        Poll();
        redisReply* reply = reply_queue.front();
        reply_queue.pop_front();
        freeReplyObject(reply);
    }

    return std::nullopt;
}

void Redis::Expire() {
    // Expiration is handled natively by Redis if not reading traces.
    if ( ! connected || ! zeek::run_state::reading_traces )
        return;

    int status = redisAsyncCommand(async_ctx, redisZRANGEBYSCORE, NULL, "ZRANGEBYSCORE %s_expire -inf %f",
                                   key_prefix.data(), run_state::network_time);

    if ( status == REDIS_ERR ) {
        // TODO: do something with the error?
        printf("ZRANGEBYSCORE command failed: %s\n", async_ctx->errstr);
        return;
    }

    ++active_ops;

    // Expire always happens in a synchronous fashion. Block here until we've received
    // a response.
    Poll();
    redisReply* reply = reply_queue.front();
    reply_queue.pop_front();

    if ( reply && reply->elements == 0 ) {
        freeReplyObject(reply);
        return;
    }

    // TODO: it's possible to pass multiple keys to a DEL operation but it requires
    // building an array of the strings, building up the DEL command with entries,
    // and passing the array as a block somehow. There's no guarantee it'd be faster
    // anyways.
    for ( size_t i = 0; i < reply->elements; i++ ) {
        status =
            redisAsyncCommand(async_ctx, redisGeneric, NULL, "DEL %s:%s", key_prefix.data(), reply->element[i]->str);
        ++active_ops;
        Poll();
    }

    // Remove all of the elements from the range-set that match the time range.
    redisAsyncCommand(async_ctx, redisGeneric, NULL, "ZREMRANGEBYSCORE %s_expire -inf %f", key_prefix.data(),
                      run_state::network_time);

    ++active_ops;
    Poll();

    // This can't be freed until the other commands finish because the memory for
    // the strings doesn't get copied when making the DEL commands.
    //    freeReplyObject(reply);
}

void Redis::HandlePutResult(redisReply* reply, ErrorResultCallback* callback) {
    --active_ops;

    if ( callback ) {
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
    else
        reply_queue.push_back(reply);
}

void Redis::HandleGetResult(redisReply* reply, ValResultCallback* callback) {
    --active_ops;

    if ( callback ) {
        ValResult res;
        if ( ! connected )
            res = zeek::unexpected<std::string>("Connection is not open");
        else
            res = ParseGetReply(reply);

        callback->Complete(res);
        freeReplyObject(reply);
        delete callback;
    }
    else {
        reply_queue.push_back(reply);
    }
}

void Redis::HandleEraseResult(redisReply* reply, ErrorResultCallback* callback) {
    --active_ops;

    if ( callback ) {
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
    else
        reply_queue.push_back(reply);
}

void Redis::HandleZRANGEBYSCORE(redisReply* reply) {
    --active_ops;
    reply_queue.push_back(reply);
}

void Redis::OnConnect(int status) {
    DBG_LOG(DBG_STORAGE, "Redis backend: connection event");
    --active_ops;

    if ( status == REDIS_OK ) {
        connected = true;
        return;
    }

    // TODO: we could attempt to reconnect here
}

void Redis::OnDisconnect(int status) {
    DBG_LOG(DBG_STORAGE, "Redis backend: disconnection event");
    --active_ops;

    if ( status == REDIS_OK ) {
        // TODO: this was an intentional disconnect, nothing to do?
    }
    else {
        // TODO: this was unintentional, should we reconnect?
    }

    connected = false;
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

    return res;
}

void Redis::Poll() {
    while ( active_ops > 0 )
        int status = redisPollTick(async_ctx, 0.5);
}

} // namespace zeek::storage::backend::redis
