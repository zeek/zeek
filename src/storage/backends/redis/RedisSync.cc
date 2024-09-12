// See the file "COPYING" in the main distribution directory for copyright.

#include "RedisSync.h"

#include "zeek/Func.h"
#include "zeek/Val.h"

#include "hiredis/hiredis.h"

namespace zeek::storage::backends::redis {

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
ErrorResult RedisSync::DoOpen(RecordValPtr config) {
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

    ctx = redisConnectWithOptions(&opt);
    if ( ctx == nullptr || ctx->err ) {
        if ( ctx )
            return util::fmt("Failed to open connection to Redis server at %s", server_addr.c_str());
        else
            return util::fmt("Failed to open connection to Redis server at %s: %s", server_addr.c_str(), ctx->errstr);
    }

    key_prefix = config->GetField<StringVal>("key_prefix")->ToStdString();

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void RedisSync::Done() {
    if ( ctx ) {
        redisFree(ctx);
        ctx = nullptr;
    }
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult RedisSync::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time,
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

    redisReply* reply;
    if ( expiration_time > 0.0 )
        reply = (redisReply*)redisCommand(ctx, format.c_str(), key_prefix.data(), json_key.data(), json_value.data(),
                                          static_cast<uint64_t>(expiration_time * 1e6));
    else
        reply = (redisReply*)redisCommand(ctx, format.c_str(), key_prefix.data(), json_key.data(), json_value.data());

    if ( ! reply )
        return util::fmt("Put operation failed: %s", ctx->errstr);

    freeReplyObject(reply);

    return std::nullopt;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult RedisSync::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( ! ctx )
        return nonstd::unexpected<std::string>("Connection is not open");

    redisReply* reply =
        (redisReply*)redisCommand(ctx, "GET %s:%s", key_prefix.data(), key->ToJSON()->ToStdStringView().data());

    if ( ! reply )
        return nonstd::unexpected<std::string>(util::fmt("Get operation failed: %s", ctx->errstr));

    auto val = zeek::detail::ValFromJSON(reply->str, val_type, Func::nil);
    freeReplyObject(reply);

    if ( std::holds_alternative<ValPtr>(val) ) {
        ValPtr val_v = std::get<ValPtr>(val);
        return val_v;
    }
    else {
        return nonstd::unexpected<std::string>(std::get<std::string>(val));
    }

    return nonstd::unexpected<std::string>("DoGet not implemented");
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult RedisSync::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    redisReply* reply =
        (redisReply*)redisCommand(ctx, "DEL %s:%s", key_prefix.data(), key->ToJSON()->ToStdStringView().data());

    if ( ! reply )
        return util::fmt("Put operation failed: %s", ctx->errstr);

    freeReplyObject(reply);

    return std::nullopt;
}

} // namespace zeek::storage::backends::redis
