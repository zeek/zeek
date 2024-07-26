// See the file "COPYING" in the main distribution directory for copyright.

#include "Backend.h"

namespace zeek::storage {

zeek::OpaqueTypePtr detail::backend_opaque;

BoolResult Backend::Open(RecordValPtr config, TypePtr vt) {
    auto res = DoOpen(std::move(config), vt);
    val_type = std::move(vt);
    return res;
}

BoolResult Backend::Store(ValPtr key, ValPtr value, bool overwrite) {
    if ( ! same_type(value->GetType(), val_type) )
        return {false, "storage: value type passed does not match value type for backend"};

    // The intention for this method is to do some other heavy lifting in regard
    // to backends that need to pass data through the manager instead of directly
    // through the workers. For the first versions of the storage framework it
    // just calls the backend itself directly.
    return DoStore(std::move(key), std::move(value), overwrite);
}

ValResult Backend::Retrieve(ValPtr key) {
    // See the note in Store().
    return DoRetrieve(std::move(key));
}

BoolResult Backend::Erase(ValPtr key) {
    // See the note in Store().
    return DoErase(std::move(key));
}

} // namespace zeek::storage
