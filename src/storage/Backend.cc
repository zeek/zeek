// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Backend.h"

#include "zeek/Desc.h"
#include "zeek/Trigger.h"
#include "zeek/broker/Data.h"

namespace zeek::storage {

ResultCallback::ResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc)
    : trigger(std::move(trigger)), assoc(assoc) {}

ResultCallback::~ResultCallback() {}

void ResultCallback::Timeout() {
    if ( ! IsSyncCallback() ) {
        auto v = make_intrusive<StringVal>("Timeout during request");
        trigger->Cache(assoc, v.get());
    }
}

void ResultCallback::ValComplete(Val* result) {
    if ( ! IsSyncCallback() ) {
        trigger->Cache(assoc, result);
        trigger->Release();
    }

    Unref(result);
}

ErrorResultCallback::ErrorResultCallback(IntrusivePtr<zeek::detail::trigger::Trigger> trigger, const void* assoc)
    : ResultCallback(std::move(trigger), assoc) {}

void ErrorResultCallback::Complete(const ErrorResult& res) {
    if ( IsSyncCallback() )
        result = res;

    zeek::Val* val_result;

    if ( res )
        val_result = new StringVal(res.value());
    else
        val_result = val_mgr->Bool(true).get();

    ValComplete(val_result);
}

ValResultCallback::ValResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc)
    : ResultCallback(std::move(trigger), assoc) {}

void ValResultCallback::Complete(const ValResult& res) {
    if ( IsSyncCallback() )
        result = res;

    static auto val_result_type = zeek::id::find_type<zeek::RecordType>("val_result");
    auto* val_result = new zeek::RecordVal(val_result_type);

    if ( res )
        val_result->Assign(0, res.value());
    else
        val_result->Assign(1, zeek::make_intrusive<StringVal>(res.error()));

    ValComplete(val_result);
}

OpenResultCallback::OpenResultCallback(detail::BackendHandleVal* backend) : ResultCallback(), backend(backend) {}

OpenResultCallback::OpenResultCallback(IntrusivePtr<zeek::detail::trigger::Trigger> trigger, const void* assoc,
                                       detail::BackendHandleVal* backend)
    : ResultCallback(std::move(trigger), assoc), backend(backend) {}

void OpenResultCallback::Complete(const ErrorResult& res) {
    if ( IsSyncCallback() )
        result = res;

    zeek::Val* val_result;

    if ( res )
        val_result = new StringVal(res.value());
    else
        val_result = backend;

    ValComplete(val_result);
}

ErrorResult Backend::Open(RecordValPtr options, TypePtr kt, TypePtr vt, OpenResultCallback* cb) {
    key_type = std::move(kt);
    val_type = std::move(vt);

    return DoOpen(std::move(options));
}

ErrorResult Backend::Close(ErrorResultCallback* cb) { return DoClose(cb); }

ErrorResult Backend::Put(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    // The intention for this method is to do some other heavy lifting in regard
    // to backends that need to pass data through the manager instead of directly
    // through the workers. For the first versions of the storage framework it
    // just calls the backend itself directly.
    if ( ! same_type(key->GetType(), key_type) )
        return util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                         obj_desc_short(key->GetType().get()).c_str(), key_type->GetName().c_str());
    if ( ! same_type(value->GetType(), val_type) )
        return util::fmt("type of value passed (%s) does not match backend's value type (%s)",
                         obj_desc_short(value->GetType().get()).c_str(), val_type->GetName().c_str());

    return DoPut(std::move(key), std::move(value), overwrite, expiration_time, cb);
}

ValResult Backend::Get(ValPtr key, ValResultCallback* cb) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) )
        return zeek::unexpected<std::string>(util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                                                       key->GetType()->GetName().c_str(), key_type->GetName().c_str()));

    return DoGet(std::move(key), cb);
}

ErrorResult Backend::Erase(ValPtr key, ErrorResultCallback* cb) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) )
        return util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                         key->GetType()->GetName().c_str(), key_type->GetName().c_str());

    return DoErase(std::move(key), cb);
}

void Backend::CompleteCallback(ValResultCallback* cb, const ValResult& data) const {
    cb->Complete(data);
    if ( ! cb->IsSyncCallback() ) {
        delete cb;
    }
}

void Backend::CompleteCallback(ErrorResultCallback* cb, const ErrorResult& data) const {
    cb->Complete(data);
    if ( ! cb->IsSyncCallback() ) {
        delete cb;
    }
}

void Backend::CompleteCallback(OpenResultCallback* cb, const ErrorResult& data) const {
    cb->Complete(data);
    if ( ! cb->IsSyncCallback() ) {
        delete cb;
    }
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
