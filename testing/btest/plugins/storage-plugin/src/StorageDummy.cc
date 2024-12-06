// See the file "COPYING" in the main distribution directory for copyright.

#include "StorageDummy.h"

#include "zeek/Func.h"
#include "zeek/Val.h"

namespace btest::storage::backend {

zeek::storage::BackendPtr StorageDummy::Instantiate(std::string_view tag) {
    return zeek::make_intrusive<StorageDummy>(tag);
}

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
zeek::storage::ErrorResult StorageDummy::DoOpen(zeek::RecordValPtr options) {
    bool open_fail = options->GetField<zeek::BoolVal>("open_fail")->Get();
    if ( open_fail )
        return "open_fail was set to true, returning error";

    open = true;

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void StorageDummy::Close() { open = false; }

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
zeek::storage::ErrorResult StorageDummy::DoPut(zeek::ValPtr key, zeek::ValPtr value, bool overwrite,
                                               double expiration_time) {
    auto json_key = key->ToJSON()->ToStdString();
    auto json_value = value->ToJSON()->ToStdString();
    data[json_key] = json_value;
    return std::nullopt;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
zeek::storage::ValResult StorageDummy::DoGet(zeek::ValPtr key) {
    auto json_key = key->ToJSON();
    auto it = data.find(json_key->ToStdString());
    if ( it == data.end() )
        return zeek::unexpected<std::string>("Failed to find key");

    auto val = zeek::detail::ValFromJSON(it->second.c_str(), val_type, zeek::Func::nil);
    if ( std::holds_alternative<zeek::ValPtr>(val) ) {
        zeek::ValPtr val_v = std::get<zeek::ValPtr>(val);
        return val_v;
    }

    return zeek::unexpected<std::string>(std::get<std::string>(val));
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
zeek::storage::ErrorResult StorageDummy::DoErase(zeek::ValPtr key) {
    auto json_key = key->ToJSON();
    auto it = data.find(json_key->ToStdString());
    if ( it == data.end() )
        return "Failed to find key";

    data.erase(it);
    return std::nullopt;
}

} // namespace btest::storage::backend
