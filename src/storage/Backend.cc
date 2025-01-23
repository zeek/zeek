// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Backend.h"

#include "zeek/Desc.h"
#include "zeek/RunState.h"
#include "zeek/Trigger.h"
#include "zeek/broker/Data.h"
#include "zeek/storage/Manager.h"

namespace zeek::storage {

ResultCallback::ResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc)
    : trigger(std::move(trigger)), assoc(assoc) {}

ResultCallback::~ResultCallback() {}

void ResultCallback::Timeout() {
    auto v = make_intrusive<StringVal>("Timeout during request");
    trigger->Cache(assoc, v.get());
}

void ResultCallback::ValComplete(Val* result) {
    trigger->Cache(assoc, result);
    Unref(result);
    trigger->Release();
}

ErrorResultCallback::ErrorResultCallback(IntrusivePtr<zeek::detail::trigger::Trigger> trigger, const void* assoc)
    : ResultCallback(std::move(trigger), assoc) {}

void ErrorResultCallback::Complete(const ErrorResult& res) {
    zeek::Val* result;

    if ( res )
        result = new StringVal(res.value());
    else
        result = val_mgr->Bool(true).get();

    ValComplete(result);
}

ValResultCallback::ValResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc)
    : ResultCallback(std::move(trigger), assoc) {}

void ValResultCallback::Complete(const ValResult& res) {
    static auto val_result_type = zeek::id::find_type<zeek::RecordType>("val_result");
    auto* result = new zeek::RecordVal(val_result_type);

    if ( res )
        result->Assign(0, res.value());
    else
        result->Assign(1, zeek::make_intrusive<StringVal>(res.error()));

    ValComplete(result);
}

OpenResultCallback::OpenResultCallback(IntrusivePtr<zeek::detail::trigger::Trigger> trigger, const void* assoc,
                                       detail::BackendHandleVal* backend)
    : ResultCallback(std::move(trigger), assoc), backend(backend) {}

void OpenResultCallback::Complete(const ErrorResult& res) {
    zeek::Val* result;

    if ( res ) {
        result = new StringVal(res.value());
    }
    else {
        storage_mgr->AddBackendToMap(backend->backend);
        result = backend;
    }

    ValComplete(result);
}

ErrorResult Backend::Open(RecordValPtr options, TypePtr kt, TypePtr vt, OpenResultCallback* cb) {
    key_type = std::move(kt);
    val_type = std::move(vt);

    auto res = DoOpen(std::move(options));

    if ( (! native_async || zeek::run_state::reading_traces) && cb ) {
        cb->Complete(res);
        delete cb;
    }

    return res;
}

ErrorResult Backend::Close(ErrorResultCallback* cb) {
    auto res = DoClose(cb);

    if ( (! native_async || zeek::run_state::reading_traces) && cb ) {
        cb->Complete(res);
        delete cb;
    }

    return res;
}

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

    auto res = DoPut(std::move(key), std::move(value), overwrite, expiration_time, cb);

    if ( (! native_async || zeek::run_state::reading_traces) && cb ) {
        cb->Complete(res);
        delete cb;
    }

    return res;
}

ValResult Backend::Get(ValPtr key, ValResultCallback* cb) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) )
        return zeek::unexpected<std::string>(util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                                                       key->GetType()->GetName().c_str(), key_type->GetName().c_str()));

    auto res = DoGet(std::move(key), cb);

    if ( (! native_async || zeek::run_state::reading_traces) && cb ) {
        cb->Complete(res);
        delete cb;
    }

    return res;
}

ErrorResult Backend::Erase(ValPtr key, ErrorResultCallback* cb) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) )
        return util::fmt("type of key passed (%s) does not match backend's key type (%s)",
                         key->GetType()->GetName().c_str(), key_type->GetName().c_str());

    auto res = DoErase(std::move(key), cb);

    if ( (! native_async || zeek::run_state::reading_traces) && cb ) {
        cb->Complete(res);
        delete cb;
    }

    return res;
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
