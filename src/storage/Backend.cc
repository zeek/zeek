// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Backend.h"

#include "zeek/Trigger.h"
#include "zeek/broker/Data.h"
#include "zeek/storage/ReturnCode.h"
#include "zeek/storage/storage-events.bif.h"

namespace zeek::storage {

RecordValPtr OperationResult::BuildVal() { return MakeVal(code, err_str, value); }

RecordValPtr OperationResult::MakeVal(EnumValPtr code, std::string_view err_str, ValPtr value) {
    static auto op_result_type = zeek::id::find_type<zeek::RecordType>("Storage::OperationResult");

    auto rec = zeek::make_intrusive<zeek::RecordVal>(op_result_type);
    rec->Assign(0, std::move(code));
    if ( ! err_str.empty() )
        rec->Assign(1, std::string{err_str});
    if ( value )
        rec->Assign(2, std::move(value));

    return rec;
}

ResultCallback::ResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc)
    : trigger(std::move(trigger)), assoc(assoc) {}

void ResultCallback::Timeout() {
    static const auto& op_result_type = zeek::id::find_type<zeek::RecordType>("Storage::OperationResult");

    if ( ! IsSyncCallback() )
        trigger->Cache(assoc, OperationResult::MakeVal(ReturnCode::TIMEOUT).release());
}

void ResultCallback::Complete(OperationResult res) {
    // If this is a sync callback, there isn't a trigger to process. Store the result and bail.
    if ( IsSyncCallback() ) {
        result = std::move(res);
        return;
    }

    auto res_val = res.BuildVal();
    trigger->Cache(assoc, res_val.get());
    trigger->Release();
}

OpenResultCallback::OpenResultCallback(IntrusivePtr<detail::BackendHandleVal> backend)
    : ResultCallback(), backend(std::move(backend)) {}

OpenResultCallback::OpenResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc,
                                       IntrusivePtr<detail::BackendHandleVal> backend)
    : ResultCallback(std::move(trigger), assoc), backend(std::move(backend)) {}

void OpenResultCallback::Complete(OperationResult res) {
    if ( res.code == ReturnCode::SUCCESS ) {
        backend->backend->EnqueueBackendOpened();
    }

    // Set the result's value to the backend so that it ends up in the result getting either
    // passed back to the trigger or the one stored for sync backends.
    res.value = backend;

    ResultCallback::Complete(std::move(res));
}

OperationResult Backend::Open(OpenResultCallback* cb, RecordValPtr options, TypePtr kt, TypePtr vt) {
    key_type = std::move(kt);
    val_type = std::move(vt);
    backend_options = options;

    auto ret = DoOpen(cb, std::move(options));
    if ( ! ret.value )
        ret.value = cb->Backend();

    return ret;
}

OperationResult Backend::Close(ResultCallback* cb) { return DoClose(cb); }

OperationResult Backend::Put(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite, double expiration_time) {
    // The intention for this method is to do some other heavy lifting in regard
    // to backends that need to pass data through the manager instead of directly
    // through the workers. For the first versions of the storage framework it
    // just calls the backend itself directly.
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCode::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }
    if ( ! same_type(value->GetType(), val_type) ) {
        auto ret = OperationResult{ReturnCode::VAL_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoPut(cb, std::move(key), std::move(value), overwrite, expiration_time);
}

OperationResult Backend::Get(ResultCallback* cb, ValPtr key) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCode::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoGet(cb, std::move(key));
}

OperationResult Backend::Erase(ResultCallback* cb, ValPtr key) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCode::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoErase(cb, std::move(key));
}

void Backend::CompleteCallback(ResultCallback* cb, const OperationResult& data) const {
    cb->Complete(data);
    if ( ! cb->IsSyncCallback() ) {
        delete cb;
    }
}

void Backend::EnqueueBackendOpened() {
    event_mgr.Enqueue(Storage::backend_opened, make_intrusive<StringVal>(Tag()), backend_options);
}

void Backend::EnqueueBackendLost(std::string_view reason) {
    event_mgr.Enqueue(Storage::backend_lost, make_intrusive<StringVal>(Tag()), backend_options,
                      make_intrusive<StringVal>(reason));
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
