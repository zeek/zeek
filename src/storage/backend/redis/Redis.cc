// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/backend/redis/Redis.h"

#include <algorithm>
#include <cinttypes>

#include "zeek/DebugLogger.h"
#include "zeek/Func.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"
#include "zeek/storage/ReturnCode.h"

#include "hiredis/adapters/poll.h"
#include "hiredis/async.h"
#include "hiredis/hiredis.h"

// Anonymous callback handler methods for the hiredis async API.
namespace {

class Tracer {
public:
    Tracer(const std::string& where) : where(where) {} // DBG_LOG(zeek::DBG_STORAGE, "%s", where.c_str()); }
    ~Tracer() {}                                       // DBG_LOG(zeek::DBG_STORAGE, "%s done", where.c_str()); }
    std::string where;
};

/**
 * Callback handler for OnConnect events from hiredis.
 *
 * @param ctx The async context that called this callback.
 * @param status The status of the connection attempt.
 */
void redisOnConnect(const redisAsyncContext* ctx, int status) {
    auto t = Tracer("connect");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->OnConnect(status);
}

/**
 * Callback handler for OnDisconnect events from hiredis.
 *
 * @param ctx The async context that called this callback.
 * @param status The status of the disconnection attempt.
 */
void redisOnDisconnect(const redisAsyncContext* ctx, int status) {
    auto t = Tracer("disconnect");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->OnDisconnect(status);
}

/**
 * Callback handler for SET commands.
 *
 * @param ctx The async context that called this callback.
 * @param reply The reply from the server for the command.
 * @param privdata A pointer to private data passed in the command.
 */
void redisPut(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("put");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    auto callback = static_cast<zeek::storage::ResultCallback*>(privdata);
    backend->HandlePutResult(static_cast<redisReply*>(reply), callback);
}

/**
 * Callback handler for GET commands.
 *
 * @param ctx The async context that called this callback.
 * @param reply The reply from the server for the command.
 * @param privdata A pointer to private data passed in the command.
 */
void redisGet(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("get");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    auto callback = static_cast<zeek::storage::ResultCallback*>(privdata);
    backend->HandleGetResult(static_cast<redisReply*>(reply), callback);
}

/**
 * Callback handler for DEL commands.
 *
 * @param ctx The async context that called this callback.
 * @param reply The reply from the server for the command.
 * @param privdata A pointer to private data passed in the command.
 */
void redisErase(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("erase");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    auto callback = static_cast<zeek::storage::ResultCallback*>(privdata);
    backend->HandleEraseResult(static_cast<redisReply*>(reply), callback);
}

/**
 * Callback handler for ZADD commands.
 *
 * @param ctx The async context that called this callback.
 * @param reply The reply from the server for the command.
 * @param privdata A pointer to private data passed in the command.
 */
void redisZADD(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("zadd");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);

    // We don't care about the reply from the ZADD, mostly because blocking to poll
    // for it adds a bunch of complication to DoPut() with having to handle the
    // reply from SET first.
    backend->HandleGeneric(nullptr);
    freeReplyObject(reply);
}

/**
 * Callback handler for commands where there isn't a specific handler in the Redis class.
 *
 * @param ctx The async context that called this callback.
 * @param reply The reply from the server for the command.
 * @param privdata A pointer to private data passed in the command.
 */
void redisGeneric(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("generic");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->HandleGeneric(static_cast<redisReply*>(reply));
}

/**
 * Callback handler for ZADD commands.
 *
 * @param ctx The async context that called this callback.
 * @param reply The reply from the server for the command.
 * @param privdata A pointer to private data passed in the command.
 */
void redisINFO(redisAsyncContext* ctx, void* reply, void* privdata) {
    auto t = Tracer("generic");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(ctx->data);
    backend->HandleInfoResult(static_cast<redisReply*>(reply));
}

// Because we called redisPollAttach in DoOpen(), privdata here is a
// redisPollEvents object. We can go through that object to get the context's
// data, which contains the backend. Because we overrode these callbacks in
// DoOpen, we still want to mimic their callbacks to redisPollTick functions
// correctly.
//
// Additionally, if we're in the middle of running a manual Expire() because
// we're reading a pcap, don't add the file descriptor into iosource_mgr. Manual
// calls to Poll() during that will handle reading/writing any data, and we
// don't want the contention with the main loop.

/**
 * Callback from hiredis when a new reader is added to the context. This is called when
 * data is ready to be read from the context for a command.
 *
 * @param privdata Private data passed back to the callback when it fires. We use this to
 * get access to the redis backend object.
 */
void redisAddRead(void* privdata) {
    auto t = Tracer("addread");
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->reading == 0 && ! backend->ExpireRunning() )
        zeek::iosource_mgr->RegisterFd(rpe->fd, backend, zeek::iosource::IOSource::READ);
    rpe->reading = 1;
}

/**
 * Callback from hiredis when a new reader is added to the context. This is called when no
 * more data is ready to be read from the context for a command.
 *
 * @param privdata Private data passed back to the callback when it fires. We use this to
 * get access to the redis backend object.
 */
void redisDelRead(void* privdata) {
    auto t = Tracer("delread");
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->reading == 1 && ! backend->ExpireRunning() )
        zeek::iosource_mgr->UnregisterFd(rpe->fd, backend, zeek::iosource::IOSource::READ);
    rpe->reading = 0;
}

/**
 * Callback from hiredis when a new writer is added to the context. This is called when
 * data is ready to be written to the context for a command.
 *
 * @param privdata Private data passed back to the callback when it fires. We use this to
 * get access to the redis backend object.
 */
void redisAddWrite(void* privdata) {
    auto t = Tracer("addwrite");
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->writing == 0 && ! backend->ExpireRunning() )
        zeek::iosource_mgr->RegisterFd(rpe->fd, backend, zeek::iosource::IOSource::WRITE);
    rpe->writing = 1;
}

/**
 * Callback from hiredis when a writer is removed from the context. This is called when no
 * more data is ready to be written to the context for a command.
 *
 * @param privdata Private data passed back to the callback when it fires. We use this to
 * get access to the redis backend object.
 */
void redisDelWrite(void* privdata) {
    auto rpe = static_cast<redisPollEvents*>(privdata);
    auto t = Tracer("delwrite");
    auto backend = static_cast<zeek::storage::backend::redis::Redis*>(rpe->context->data);

    if ( rpe->writing == 1 && ! backend->ExpireRunning() )
        zeek::iosource_mgr->UnregisterFd(rpe->fd, backend, zeek::iosource::IOSource::WRITE);
    rpe->writing = 0;
}

// Creates a unique_lock based on a condition against a mutex. This is used to
// conditionally lock the expire_mutex. We only need to do it while reading
// pcaps. The only thread contention happens during Expire(), which only happens
// when reading pcaps. It's not worth the cycles to lock the mutex otherwise,
// and hiredis will deal with other cross-command contention correctly as long
// as it's in a single thread.
std::unique_lock<std::mutex> conditionally_lock(bool condition, std::mutex& mutex) {
    return condition ? std::unique_lock<std::mutex>(mutex) : std::unique_lock<std::mutex>();
}

} // namespace

namespace zeek::storage::backend::redis {

constexpr char REQUIRED_VERSION[] = "6.2.0";

storage::BackendPtr Redis::Instantiate() { return make_intrusive<Redis>(); }

/**
 * Called by the manager system to open the backend.
 */
OperationResult Redis::DoOpen(OpenResultCallback* cb, RecordValPtr options) {
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
        if ( ! unix_sock ) {
            return {ReturnCode::CONNECTION_FAILED,
                    "Either server_host/server_port or server_unix_socket must be set in Redis options record"};
        }

        server_addr = unix_sock->ToStdString();
        REDIS_OPTIONS_SET_UNIX(&opt, server_addr.c_str());
    }

    opt.options |= REDIS_OPT_PREFER_IPV4;
    opt.options |= REDIS_OPT_NOAUTOFREEREPLIES;

    auto connect_timeout_opt = backend_options->GetField<IntervalVal>("connect_timeout")->Get();
    struct timeval timeout = util::double_to_timeval(connect_timeout_opt);
    opt.connect_timeout = &timeout;

    // The connection request below should be operation #1.
    active_ops = 1;

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
        return {ReturnCode::CONNECTION_FAILED, errmsg};
    }

    // There's no way to pass privdata down to the connect handler like there is for
    // the other callbacks. Store the open callback so that it can be dealt with from
    // OnConnect().
    open_cb = cb;

    // TODO: Sort out how to pass the zeek callbacks for both open/done to the async
    // callbacks from hiredis so they can return errors.

    // The context is passed to the handler methods. Setting this data object
    // pointer allows us to look up the backend in the handlers.
    async_ctx->data = this;

    redisPollAttach(async_ctx);
    redisAsyncSetConnectCallback(async_ctx, redisOnConnect);
    redisAsyncSetDisconnectCallback(async_ctx, redisOnDisconnect);

    auto op_timeout_opt = backend_options->GetField<IntervalVal>("operation_timeout")->Get();
    struct timeval op_timeout = util::double_to_timeval(op_timeout_opt);
    redisAsyncSetTimeout(async_ctx, op_timeout);

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

    return {ReturnCode::IN_PROGRESS};
}

/**
 * Finalizes the backend when it's being closed.
 */
OperationResult Redis::DoClose(ResultCallback* cb) {
    auto locked_scope = conditionally_lock(zeek::run_state::reading_traces, expire_mutex);

    connected = false;
    close_cb = cb;

    redisAsyncDisconnect(async_ctx);
    ++active_ops;

    return {ReturnCode::IN_PROGRESS};
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
OperationResult Redis::DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite, double expiration_time) {
    // The async context will queue operations until it's connected fully.
    if ( ! connected && ! async_ctx )
        return {ReturnCode::NOT_CONNECTED};

    auto locked_scope = conditionally_lock(zeek::run_state::reading_traces, expire_mutex);

    std::string format = "SET %s:%b %b";
    if ( ! overwrite )
        format.append(" NX");

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    auto val_data = serializer->Serialize(value);
    if ( ! val_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize value"};

    int status;
    // Use built-in expiration if reading live data, since time will move
    // forward consistently. If reading pcaps, we'll do something else.
    if ( expiration_time > 0.0 && ! zeek::run_state::reading_traces ) {
        format.append(" PXAT %" PRIu64);
        status = redisAsyncCommand(async_ctx, redisPut, cb, format.c_str(), key_prefix.data(), key_data->data(),
                                   key_data->size(), val_data->data(), val_data->size(),
                                   static_cast<uint64_t>(expiration_time * 1e3));
    }
    else
        status = redisAsyncCommand(async_ctx, redisPut, cb, format.c_str(), key_prefix.data(), key_data->data(),
                                   key_data->size(), val_data->data(), val_data->size());

    if ( connected && status == REDIS_ERR )
        return {ReturnCode::OPERATION_FAILED, util::fmt("Failed to queue put operation: %s", async_ctx->errstr)};

    ++active_ops;

    // If reading pcaps insert into a secondary set that's ordered by expiration
    // time that gets checked by Expire().
    if ( expiration_time > 0.0 && zeek::run_state::reading_traces ) {
        format = "ZADD %s_expire";
        if ( ! overwrite )
            format.append(" NX");
        format += " %f %b";

        status = redisAsyncCommand(async_ctx, redisZADD, NULL, format.c_str(), key_prefix.data(), expiration_time,
                                   key_data->data(), key_data->size());
        if ( connected && status == REDIS_ERR )
            return {ReturnCode::OPERATION_FAILED, util::fmt("ZADD operation failed: %s", async_ctx->errstr)};

        ++active_ops;
    }

    return {ReturnCode::IN_PROGRESS};
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
OperationResult Redis::DoGet(ResultCallback* cb, ValPtr key) {
    // The async context will queue operations until it's connected fully.
    if ( ! connected && ! async_ctx )
        return {ReturnCode::NOT_CONNECTED};

    auto locked_scope = conditionally_lock(zeek::run_state::reading_traces, expire_mutex);

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    int status =
        redisAsyncCommand(async_ctx, redisGet, cb, "GET %s:%b", key_prefix.data(), key_data->data(), key_data->size());

    if ( connected && status == REDIS_ERR )
        return {ReturnCode::OPERATION_FAILED, util::fmt("Failed to queue get operation: %s", async_ctx->errstr)};

    ++active_ops;

    // There isn't a result to return here. That happens in HandleGetResult for
    // async operations.
    return {ReturnCode::IN_PROGRESS};
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
OperationResult Redis::DoErase(ResultCallback* cb, ValPtr key) {
    // The async context will queue operations until it's connected fully.
    if ( ! connected && ! async_ctx )
        return {ReturnCode::NOT_CONNECTED};

    auto locked_scope = conditionally_lock(zeek::run_state::reading_traces, expire_mutex);

    auto key_data = serializer->Serialize(key);
    if ( ! key_data )
        return {ReturnCode::SERIALIZATION_FAILED, "Failed to serialize key"};

    int status = redisAsyncCommand(async_ctx, redisErase, cb, "DEL %s:%b", key_prefix.data(), key_data->data(),
                                   key_data->size());

    if ( connected && status == REDIS_ERR )
        return {ReturnCode::OPERATION_FAILED, async_ctx->errstr};

    ++active_ops;

    return {ReturnCode::IN_PROGRESS};
}

void Redis::DoExpire(double current_network_time) {
    // Expiration is handled natively by Redis if not reading traces.
    if ( ! connected || ! zeek::run_state::reading_traces )
        return;

    auto locked_scope = conditionally_lock(zeek::run_state::reading_traces, expire_mutex);

    expire_running = true;

    int status = redisAsyncCommand(async_ctx, redisGeneric, NULL, "ZRANGEBYSCORE %s_expire -inf %f", key_prefix.data(),
                                   current_network_time);

    if ( status == REDIS_ERR ) {
        // TODO: do something with the error?
        printf("ZRANGEBYSCORE command failed: %s\n", async_ctx->errstr);
        expire_running = false;
        return;
    }

    ++active_ops;

    // Expire always happens in a synchronous fashion. Block here until we've received
    // a response.
    Poll();
    redisReply* reply = reply_queue.front();
    reply_queue.pop_front();

    if ( reply->elements == 0 ) {
        freeReplyObject(reply);
        expire_running = false;
        return;
    }

    std::vector<std::string_view> elements;
    elements.reserve(reply->elements);

    for ( size_t i = 0; i < reply->elements; i++ )
        elements.emplace_back(reply->element[i]->str, reply->element[i]->len);

    // TODO: it's possible to pass multiple keys to a DEL operation but it requires
    // building an array of the strings, building up the DEL command with entries,
    // and passing the array as a block somehow. There's no guarantee it'd be faster
    // anyways.
    for ( const auto& e : elements ) {
        // redisAsyncCommand usually takes a printf-style string, except the parser used by
        // hiredis doesn't handle lengths passed with strings correctly (it hangs indefinitely).
        // Use util::fmt here instead it handles it.
        status = redisAsyncCommand(async_ctx, redisGeneric, NULL,
                                   util::fmt("DEL %s:%.*s", key_prefix.data(), static_cast<int>(e.size()), e.data()));
        ++active_ops;
        Poll();

        redisReply* del_reply = reply_queue.front();
        reply_queue.pop_front();
        freeReplyObject(del_reply);
        // TODO: do we care if this failed?
    }

    freeReplyObject(reply);

    // Remove all of the elements from the range-set that match the time range.
    redisAsyncCommand(async_ctx, redisGeneric, NULL, "ZREMRANGEBYSCORE %s_expire -inf %f", key_prefix.data(),
                      current_network_time);

    ++active_ops;
    Poll();

    redisReply* rem_range_reply = reply_queue.front();
    reply_queue.pop_front();
    freeReplyObject(rem_range_reply);
    // TODO: do we care if this failed?
}

void Redis::HandlePutResult(redisReply* reply, ResultCallback* callback) {
    --active_ops;

    OperationResult res{ReturnCode::SUCCESS};
    if ( ! connected )
        res = {ReturnCode::NOT_CONNECTED};
    else if ( ! reply )
        res = {ReturnCode::OPERATION_FAILED, "put operation returned null reply"};
    else if ( reply->type == REDIS_REPLY_NIL )
        // For a SET operation, a NIL reply indicates a conflict with the NX flag.
        res = {ReturnCode::KEY_EXISTS};
    else if ( reply->type == REDIS_REPLY_ERROR )
        res = ParseReplyError("put", reply->str);

    freeReplyObject(reply);
    CompleteCallback(callback, res);
}

void Redis::HandleGetResult(redisReply* reply, ResultCallback* callback) {
    --active_ops;

    OperationResult res;
    if ( ! connected )
        res = {ReturnCode::NOT_CONNECTED};
    if ( ! reply )
        res = {ReturnCode::OPERATION_FAILED, "get operation returned null reply"};
    else if ( reply->type == REDIS_REPLY_NIL )
        res = {ReturnCode::KEY_NOT_FOUND};
    else if ( reply->type == REDIS_REPLY_ERROR )
        res = ParseReplyError("get", reply->str);
    else {
        auto val = serializer->Unserialize({(std::byte*)reply->str, reply->len}, val_type);
        if ( val )
            res = {ReturnCode::SUCCESS, "", val.value()};
        else
            res = {ReturnCode::OPERATION_FAILED, val.error()};
    }

    freeReplyObject(reply);
    CompleteCallback(callback, res);
}

void Redis::HandleEraseResult(redisReply* reply, ResultCallback* callback) {
    --active_ops;

    OperationResult res{ReturnCode::SUCCESS};

    if ( ! connected )
        res = {ReturnCode::NOT_CONNECTED};
    else if ( ! reply )
        res = {ReturnCode::OPERATION_FAILED, "erase operation returned null reply"};
    else if ( reply->type == REDIS_REPLY_ERROR )
        res = ParseReplyError("erase", reply->str);

    freeReplyObject(reply);
    CompleteCallback(callback, res);
}

void Redis::HandleGeneric(redisReply* reply) {
    --active_ops;

    if ( reply )
        reply_queue.push_back(reply);
}

void Redis::HandleInfoResult(redisReply* reply) {
    DBG_LOG(DBG_STORAGE, "Redis backend: info event");
    --active_ops;

    auto lines = util::split(std::string{reply->str}, "\r\n");

    OperationResult res = {ReturnCode::CONNECTION_FAILED};
    if ( lines.empty() )
        res.err_str = "INFO command return zero entries";
    else {
        std::string_view version_sv{REQUIRED_VERSION};

        for ( const auto& e : lines ) {
            // Skip empty lines and comments
            if ( e.empty() || e[0] == '#' )
                continue;

            // We only care about the redis_version entry. Skip anything else.
            if ( ! util::starts_with(e, "redis_version:") )
                continue;

            auto splits = util::split(e, ':');
            DBG_LOG(DBG_STORAGE, "Redis backend: found server version %s", splits[1].c_str());
            if ( std::lexicographical_compare(splits[1].begin(), splits[1].end(), version_sv.begin(),
                                              version_sv.end()) )
                res.err_str = util::fmt("Redis server version is too low: Found %s, need %s", splits[1].c_str(),
                                        REQUIRED_VERSION);
            else {
                connected = true;
                res.code = ReturnCode::SUCCESS;
            }
        }
    }

    if ( ! connected && res.err_str.empty() )
        res.err_str = "INFO command did not return server version";

    freeReplyObject(reply);
    CompleteCallback(open_cb, res);
}

void Redis::OnConnect(int status) {
    DBG_LOG(DBG_STORAGE, "Redis backend: connection event, status=%d", status);
    --active_ops;

    connected = false;
    if ( status == REDIS_OK ) {
        // Request the INFO block from the server that should contain the version information.
        status = redisAsyncCommand(async_ctx, redisINFO, NULL, "INFO server");

        if ( status == REDIS_ERR ) {
            // TODO: do something with the error?
            DBG_LOG(DBG_STORAGE, "INFO command failed: %s err=%d", async_ctx->errstr, async_ctx->err);
            CompleteCallback(open_cb,
                             {ReturnCode::OPERATION_FAILED,
                              util::fmt("INFO command failed to retrieve server info: %s", async_ctx->errstr)});
            return;
        }

        ++active_ops;
    }
    else {
        DBG_LOG(DBG_STORAGE, "Redis backend: connection failed: %s err=%d", async_ctx->errstr, async_ctx->err);
        CompleteCallback(open_cb,
                         {ReturnCode::CONNECTION_FAILED, util::fmt("Connection failed: %s", async_ctx->errstr)});
    }

    // TODO: we could attempt to reconnect here
}

void Redis::OnDisconnect(int status) {
    DBG_LOG(DBG_STORAGE, "Redis backend: disconnection event, status=%d", status);

    connected = false;
    if ( status == REDIS_ERR ) {
        // An error status indicates that the connection was lost unexpectedly and not
        // via a request from backend.
        EnqueueBackendLost(async_ctx->errstr);
    }
    else {
        --active_ops;

        EnqueueBackendLost("Client disconnected");
        CompleteCallback(close_cb, {ReturnCode::SUCCESS});
    }

    redisAsyncFree(async_ctx);
    async_ctx = nullptr;
}

void Redis::ProcessFd(int fd, int flags) {
    auto locked_scope = conditionally_lock(zeek::run_state::reading_traces, expire_mutex);

    if ( (flags & IOSource::ProcessFlags::READ) != 0 )
        redisAsyncHandleRead(async_ctx);
    if ( (flags & IOSource::ProcessFlags::WRITE) != 0 )
        redisAsyncHandleWrite(async_ctx);
}

OperationResult Redis::ParseReplyError(std::string_view op_str, std::string_view reply_err_str) const {
    if ( async_ctx->err == REDIS_ERR_TIMEOUT )
        return {ReturnCode::TIMEOUT};
    else if ( async_ctx->err == REDIS_ERR_IO )
        return {ReturnCode::OPERATION_FAILED, util::fmt("%s operation IO error: %s", op_str.data(), strerror(errno))};
    else
        return {ReturnCode::OPERATION_FAILED,
                util::fmt("%s operation failed: %s", op_str.data(), reply_err_str.data())};
}

void Redis::DoPoll() {
    while ( active_ops > 0 )
        int status = redisPollTick(async_ctx, 0.5);
}

} // namespace zeek::storage::backend::redis
