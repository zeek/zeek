// See the file "COPYING" in the main distribution directory for copyright.

#include "Backend.h"

namespace zeek::storage {

zeek::OpaqueTypePtr detail::backend_opaque;

BoolResult Backend::Open(RecordValPtr config) { return DoOpen(std::move(config)); }

BoolResult Backend::Put(ValPtr key, ValPtr value, bool overwrite) {
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

BoolResult Backend::Erase(ValPtr key) {
    // See the note in Put().
    return DoErase(std::move(key));
}

} // namespace zeek::storage
