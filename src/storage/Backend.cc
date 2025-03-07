// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Backend.h"

#include "zeek/Trigger.h"
#include "zeek/broker/Data.h"
#include "zeek/storage/ReturnCodes.h"
#include "zeek/storage/storage.bif.h"

namespace zeek::storage {

void OperationResult::FillRecordVal(const RecordValPtr& rec) {
    rec->Assign(0, code);
    if ( ! err_str.empty() )
        rec->Assign(1, zeek::make_intrusive<StringVal>(err_str));
    if ( value )
        rec->Assign(2, value);
}

ResultCallback::ResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc)
    : trigger(std::move(trigger)), assoc(assoc) {}

// ResultCallback::~ResultCallback() {}

void ResultCallback::Timeout() {
    static const auto& op_result_type = zeek::id::find_type<zeek::RecordType>("Storage::OperationResult");

    if ( ! SyncCallback() ) {
        auto op_result = make_intrusive<RecordVal>(op_result_type);
        op_result->Assign(0, ReturnCodes::TIMEOUT);

        trigger->Cache(assoc, op_result.release());
    }
}

OperationResultCallback::OperationResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc)
    : ResultCallback(std::move(trigger), assoc) {}

void OperationResultCallback::Complete(const OperationResult& res) {
    // If this is a sync callback, there isn't a trigger to process. Store the result and bail.
    if ( SyncCallback() ) {
        result = res;
        return;
    }

    static auto op_result_type = zeek::id::find_type<zeek::RecordType>("Storage::OperationResult");
    auto* op_result = new zeek::RecordVal(op_result_type);

    op_result->Assign(0, res.code);
    if ( res.code->Get() != 0 )
        op_result->Assign(1, zeek::make_intrusive<StringVal>(res.err_str));
    else
        op_result->Assign(2, res.value);

    trigger->Cache(assoc, op_result);
    trigger->Release();

    Unref(op_result);
}

OpenResultCallback::OpenResultCallback(IntrusivePtr<detail::BackendHandleVal> backend)
    : ResultCallback(), backend(std::move(backend)) {}

OpenResultCallback::OpenResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc,
                                       IntrusivePtr<detail::BackendHandleVal> backend)
    : ResultCallback(std::move(trigger), assoc), backend(std::move(backend)) {}

void OpenResultCallback::Complete(const OperationResult& res) {
    if ( res.code == ReturnCodes::SUCCESS ) {
        event_mgr.Enqueue(Storage::connection_established, make_intrusive<StringVal>(backend->backend->Tag()),
                          backend->backend->Options());
    }

    // If this is a sync callback, there isn't a trigger to process. Store the result and bail. Always
    // set result's value to the backend pointer so that it comes across in the result. This ensures
    // the handle is always available in the result even on failures.
    if ( SyncCallback() ) {
        result = res;
        result.value = backend;
        return;
    }

    static auto op_result_type = zeek::id::find_type<zeek::RecordType>("Storage::OperationResult");
    auto* op_result = new zeek::RecordVal(op_result_type);

    op_result->Assign(0, res.code);
    if ( res.code != ReturnCodes::SUCCESS )
        op_result->Assign(1, res.err_str);
    op_result->Assign(2, backend);

    trigger->Cache(assoc, op_result);
    trigger->Release();

    Unref(op_result);
}

OperationResult Backend::Open(RecordValPtr options, TypePtr kt, TypePtr vt, OpenResultCallback* cb) {
    key_type = std::move(kt);
    val_type = std::move(vt);
    backend_options = options;

    auto ret = DoOpen(std::move(options), cb);
    if ( ! ret.value )
        ret.value = cb->Backend();

    return ret;
}

OperationResult Backend::Done(OperationResultCallback* cb) { return DoDone(cb); }

OperationResult Backend::Put(ValPtr key, ValPtr value, bool overwrite, double expiration_time,
                             OperationResultCallback* cb) {
    // The intention for this method is to do some other heavy lifting in regard
    // to backends that need to pass data through the manager instead of directly
    // through the workers. For the first versions of the storage framework it
    // just calls the backend itself directly.
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCodes::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }
    if ( ! same_type(value->GetType(), val_type) ) {
        auto ret = OperationResult{ReturnCodes::VAL_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoPut(std::move(key), std::move(value), overwrite, expiration_time, cb);
}

OperationResult Backend::Get(ValPtr key, OperationResultCallback* cb) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCodes::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoGet(std::move(key), cb);
}

OperationResult Backend::Erase(ValPtr key, OperationResultCallback* cb) {
    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCodes::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoErase(std::move(key), cb);
}

void Backend::CompleteCallback(OpenResultCallback* cb, const OperationResult& data) const {
    cb->Complete(data);
    if ( ! cb->SyncCallback() ) {
        delete cb;
    }
}

void Backend::CompleteCallback(OperationResultCallback* cb, const OperationResult& data) const {
    cb->Complete(data);
    if ( ! cb->SyncCallback() ) {
        delete cb;
    }
}

void Backend::PostConnectionEstablished() {
    event_mgr.Enqueue(Storage::connection_established, make_intrusive<StringVal>(Tag()), backend_options);
}

void Backend::PostConnectionLost(std::string_view reason) {
    event_mgr.Enqueue(Storage::connection_lost, make_intrusive<StringVal>(Tag()), backend_options,
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
