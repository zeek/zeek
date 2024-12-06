// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Backend.h"

#include "zeek/broker/Data.h"

namespace zeek::storage {

ErrorResult Backend::Open(RecordValPtr config, TypePtr kt, TypePtr vt) {
    key_type = std::move(kt);
    val_type = std::move(vt);

    return DoOpen(std::move(config));
}

ErrorResult Backend::Put(ValPtr key, ValPtr value, bool overwrite, double expiration_time) {
    // The intention for this method is to do some other heavy lifting in regard
    // to backends that need to pass data through the manager instead of directly
    // through the workers. For the first versions of the storage framework it
    // just calls the backend itself directly.
    if ( ! same_type(key->GetType(), key_type) )
        return util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                         key->GetType()->GetName().c_str(), key_type->GetName().c_str());
    if ( ! same_type(value->GetType(), val_type) )
        return util::fmt("type of value passed (%s) does not match backend's value type (%s)",
                         value->GetType()->GetName().c_str(), val_type->GetName().c_str());

    return DoPut(std::move(key), std::move(value), overwrite, expiration_time);
}

ValResult Backend::Get(ValPtr key) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) )
        return nonstd::unexpected<std::string>(
            util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                      key->GetType()->GetName().c_str(), key_type->GetName().c_str()));

    return DoGet(std::move(key));
}

ErrorResult Backend::Erase(ValPtr key) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) )
        return util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                         key->GetType()->GetName().c_str(), key_type->GetName().c_str());

    return DoErase(std::move(key));
}

zeek::OpaqueTypePtr detail::backend_opaque;
IMPLEMENT_OPAQUE_VALUE(detail::BackendHandleVal)

std::optional<BrokerData> detail::BackendHandleVal::DoSerializeData() const {
    // Cannot serialize.
    return std::nullopt;
}

bool detail::BackendHandleVal::DoUnserializeData(BrokerDataView) {
    // Cannot unserialize.
    return false;
}

} // namespace zeek::storage
