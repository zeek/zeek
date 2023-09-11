// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Backend.h"

#include "zeek/broker/Data.h"

namespace zeek::storage {

ErrorResult Backend::Open(RecordValPtr options) { return DoOpen(std::move(options)); }

ErrorResult Backend::Put(ValPtr key, ValPtr value, bool overwrite) {
    // The intention for this method is to do some other heavy lifting in regard
    // to backends that need to pass data through the manager instead of directly
    // through the workers. For the first versions of the storage framework it
    // just calls the backend itself directly.
    return DoPut(std::move(key), std::move(value), overwrite);
}

ValResult Backend::Get(ValPtr key, TypePtr value_type) {
    // See the note in Put().
    return DoGet(std::move(key), std::move(value_type));
}

ErrorResult Backend::Erase(ValPtr key) {
    // See the note in Put().
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
