// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Backend.h"

#include "zeek/Desc.h"
#include "zeek/Trigger.h"
#include "zeek/broker/Data.h"
#include "zeek/storage/Manager.h"
#include "zeek/storage/ReturnCode.h"
#include "zeek/storage/storage-events.bif.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Histogram.h"
#include "zeek/telemetry/Manager.h"

namespace zeek::storage {

namespace detail {

struct OperationMetrics {
    telemetry::CounterPtr success;
    telemetry::CounterPtr fail;
    telemetry::CounterPtr timeouts;
    telemetry::HistogramPtr latency;

    OperationMetrics(const telemetry::CounterFamilyPtr& success_family, const telemetry::CounterFamilyPtr& fail_family,
                     const telemetry::CounterFamilyPtr& timeout_family,
                     const telemetry::HistogramFamilyPtr& latency_family, std::string_view operation_type,
                     std::string_view backend_type, std::string_view backend_config)
        : success(success_family->GetOrAdd(
              {{"operation", operation_type}, {"backend_type", backend_type}, {"backend_config", backend_config}})),
          fail(fail_family->GetOrAdd(
              {{"operation", operation_type}, {"backend_type", backend_type}, {"backend_config", backend_config}})),
          timeouts(timeout_family->GetOrAdd(
              {{"operation", operation_type}, {"backend_type", backend_type}, {"backend_config", backend_config}})),
          latency(latency_family->GetOrAdd(
              {{"operation", operation_type}, {"backend_type", backend_type}, {"backend_config", backend_config}})) {}
};

} // namespace detail

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
    if ( ! IsSyncCallback() )
        trigger->Cache(assoc, OperationResult::MakeVal(ReturnCode::TIMEOUT).get());

    if ( operation_metrics )
        operation_metrics->timeouts->Inc();
}

void ResultCallback::Complete(OperationResult res) {
    if ( operation_metrics ) {
        if ( res.code == ReturnCode::SUCCESS )
            operation_metrics->success->Inc();
        else
            operation_metrics->fail->Inc();

        // Store the latency between start and completion in milliseconds.
        operation_metrics->latency->Observe((util::current_time() - start_time) * 1000);
    }

    // If this is a sync callback, there isn't a trigger to process. Store the result and bail.
    if ( IsSyncCallback() ) {
        result = std::move(res);
        return;
    }

    auto res_val = res.BuildVal();
    trigger->Cache(assoc, res_val.get());
    trigger->Release();
}

void ResultCallback::InitMetrics(detail::OperationMetrics* m) {
    operation_metrics = m;
    start_time = util::current_time();
}

OpenResultCallback::OpenResultCallback(IntrusivePtr<detail::BackendHandleVal> backend)
    : ResultCallback(), backend(std::move(backend)) {}

OpenResultCallback::OpenResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc,
                                       IntrusivePtr<detail::BackendHandleVal> backend)
    : ResultCallback(std::move(trigger), assoc), backend(std::move(backend)) {}

void OpenResultCallback::Complete(OperationResult res) {
    if ( res.code == ReturnCode::SUCCESS ) {
        backend->backend->InitMetrics();
        backend->backend->EnqueueBackendOpened();
    }

    // Set the result's value to the backend so that it ends up in the result getting either
    // passed back to the trigger or the one stored for sync backends.
    res.value = backend;

    ResultCallback::Complete(std::move(res));
}

Backend::Backend(uint8_t modes, std::string_view tag_name) : modes(modes) {
    tag = storage_mgr->BackendMgr().GetComponentTag(std::string{tag_name});
    tag_str = zeek::obj_desc_short(tag.AsVal().get());
}

Backend::~Backend() {
    delete put_metrics;
    delete get_metrics;
    delete erase_metrics;
}

OperationResult Backend::Open(OpenResultCallback* cb, RecordValPtr options, TypePtr kt, TypePtr vt) {
    key_type = std::move(kt);
    val_type = std::move(vt);
    backend_options = options;

    auto stype = options->GetField<EnumVal>("serializer");
    zeek::Tag stag{stype};

    auto s = storage_mgr->InstantiateSerializer(stag);
    if ( ! s )
        return {ReturnCode::INITIALIZATION_FAILED, s.error()};

    serializer = std::move(s.value());

    auto ret = DoOpen(cb, std::move(options));
    if ( ! ret.value )
        ret.value = cb->Backend();

    // If open finished completely, init the metrics. This is the case with backends that
    // only support sync.
    if ( ret.code == ReturnCode::SUCCESS )
        InitMetrics();

    return ret;
}

OperationResult Backend::Close(ResultCallback* cb) { return DoClose(cb); }

OperationResult Backend::Put(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite, double expiration_time) {
    cb->InitMetrics(put_metrics);

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
    cb->InitMetrics(get_metrics);

    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCode::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoGet(cb, std::move(key));
}

OperationResult Backend::Erase(ResultCallback* cb, ValPtr key) {
    cb->InitMetrics(erase_metrics);

    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCode::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    return DoErase(cb, std::move(key));
}

void Backend::CompleteCallback(ResultCallback* cb, const OperationResult& data) const {
    if ( data.code == ReturnCode::TIMEOUT )
        cb->Timeout();
    else
        cb->Complete(data);

    if ( ! cb->IsSyncCallback() ) {
        delete cb;
    }
}

void Backend::EnqueueBackendOpened() { event_mgr.Enqueue(Storage::backend_opened, tag.AsVal(), backend_options); }

void Backend::EnqueueBackendLost(std::string_view reason) {
    event_mgr.Enqueue(Storage::backend_lost, tag.AsVal(), backend_options, make_intrusive<StringVal>(reason));
}

void Backend::InitMetrics() {
    if ( metrics_initialized )
        return;

    metrics_initialized = true;
    auto success_family =
        telemetry_mgr->CounterFamily("zeek", "storage_operation_success",
                                     {"operation", "backend_type", "backend_config"}, "Successful Storage Operations");
    auto fail_family =
        telemetry_mgr->CounterFamily("zeek", "storage_operation_failed",
                                     {"operation", "backend_type", "backend_config"}, "Failed Storage Operations");
    auto timeout_family =
        telemetry_mgr->CounterFamily("zeek", "storage_operation_timeout",
                                     {"operation", "backend_type", "backend_config"}, "Timeouted Storage Operations");

    double bounds[] = {0.01, 0.1, 1.0, 10.0, 100.0};
    auto latency_family = telemetry_mgr->HistogramFamily("zeek", "storage_operation_latency",
                                                         {"operation", "backend_type", "backend_config"}, bounds,
                                                         "Storage Operation Latency", "milliseconds");

    std::string metrics_config = GetConfigForMetrics();
    put_metrics = new detail::OperationMetrics(success_family, fail_family, timeout_family, latency_family, "put",
                                               Tag(), metrics_config);
    get_metrics = new detail::OperationMetrics(success_family, fail_family, timeout_family, latency_family, "get",
                                               Tag(), metrics_config);
    erase_metrics = new detail::OperationMetrics(success_family, fail_family, timeout_family, latency_family, "erase",
                                                 Tag(), metrics_config);

    bytes_stored_metric = telemetry_mgr->CounterInstance("zeek", "storage_data_stored",
                                                         {{"backend_type", Tag()}, {"backend_config", metrics_config}},
                                                         "Storage Data Stored", "bytes");
    bytes_retrieved_metric =
        telemetry_mgr->CounterInstance("zeek", "storage_data_retrieved",
                                       {{"backend_type", Tag()}, {"backend_config", metrics_config}},
                                       "Storage Data Retrieved", "bytes");
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

namespace detail {

zeek::expected<storage::detail::BackendHandleVal*, OperationResult> BackendHandleVal::CastFromAny(Val* handle) {
    // Quick exit by checking the type tag. This should be faster than doing the dynamic
    // cast below.
    if ( handle->GetType() != detail::backend_opaque )
        return zeek::unexpected<OperationResult>(
            OperationResult{ReturnCode::OPERATION_FAILED, "Invalid storage handle type"});

    auto b = dynamic_cast<storage::detail::BackendHandleVal*>(handle);

    if ( ! b )
        return zeek::unexpected<OperationResult>(
            OperationResult{ReturnCode::OPERATION_FAILED, "Invalid storage handle type"});
    else if ( ! b->backend->IsOpen() )
        return zeek::unexpected<OperationResult>(OperationResult{ReturnCode::NOT_CONNECTED, "Backend is closed"});

    return b;
}

} // namespace detail

} // namespace zeek::storage
