// See the file "COPYING" in the main distribution directory for copyright.

#include "Redis.h"

#include "zeek/Val.h"
#include "zeek/storage/backends/redis/RedisAsync.h"
#include "zeek/storage/backends/redis/RedisSync.h"

namespace zeek::storage::backends::redis {

storage::Backend* Redis::Instantiate() { return new Redis(); }

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
ErrorResult Redis::DoOpen(RecordValPtr config) {
    auto async_mode = config->GetField<BoolVal>("async_mode");
    if ( async_mode->Get() ) {
        async = new RedisAsync(val_type);
        return async->DoOpen(config);
    }
    else {
        sync = new RedisSync(val_type);
        return sync->DoOpen(config);
    }
}

/**
 * Finalizes the backend when it's being closed.
 */
void Redis::Done() {
    if ( async )
        async->Done();
    else if ( sync )
        sync->Done();
}

/**
 * Returns whether the backend is opened.
 */
bool Redis::IsOpen() {
    if ( async )
        return async->IsOpen();
    else if ( sync )
        return sync->IsOpen();

    return false;
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult Redis::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    if ( async )
        return async->DoPut(key, value, overwrite, expiration_time, cb);
    else if ( sync )
        return sync->DoPut(key, value, overwrite, expiration_time, cb);

    return "Connection is not open";
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult Redis::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( async )
        return async->DoGet(key, cb);
    else if ( sync )
        return sync->DoGet(key, cb);

    return nonstd::unexpected<std::string>("Connection is not open");
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult Redis::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( async )
        return async->DoErase(key, cb);
    else if ( sync )
        return sync->DoErase(key, cb);

    return "Connection is not open";
}

} // namespace zeek::storage::backends::redis
