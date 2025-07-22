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

OperationMetrics::OperationMetrics(const telemetry::CounterFamilyPtr& results_family,
                                   const telemetry::HistogramFamilyPtr& latency_family, std::string_view operation_type,
                                   std::string_view backend_type, std::string_view backend_config)
    : success(results_family->GetOrAdd(
          {{"operation", operation_type}, {"type", backend_type}, {"config", backend_config}, {"result", "success"}})),
      fail(results_family->GetOrAdd(
          {{"operation", operation_type}, {"type", backend_type}, {"config", backend_config}, {"result", "fail"}})),
      error(results_family->GetOrAdd(
          {{"operation", operation_type}, {"type", backend_type}, {"config", backend_config}, {"result", "error"}})),
      timeouts(results_family->GetOrAdd(
          {{"operation", operation_type}, {"type", backend_type}, {"config", backend_config}, {"result", "timeout"}})),
      latency(latency_family->GetOrAdd(
          {{"operation", operation_type}, {"type", backend_type}, {"config", backend_config}})) {}

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
    UpdateOperationMetrics(res.code);

    // If this is a sync callback, there isn't a trigger to process. Store the result and bail.
    if ( IsSyncCallback() ) {
        result = std::move(res);
        return;
    }

    auto res_val = res.BuildVal();
    trigger->Cache(assoc, res_val.get());
    trigger->Release();
}

void ResultCallback::Init(detail::OperationMetrics* m) {
    operation_metrics = m;
    start_time = util::current_time(true);
}

void ResultCallback::UpdateOperationMetrics(EnumValPtr c) {
    if ( operation_metrics ) {
        if ( c == ReturnCode::SUCCESS )
            operation_metrics->success->Inc();
        else if ( c == ReturnCode::KEY_EXISTS || c == ReturnCode::KEY_NOT_FOUND )
            operation_metrics->fail->Inc();
        else if ( c != ReturnCode::IN_PROGRESS )
            operation_metrics->error->Inc();

        // Store the latency between start and completion in milliseconds.
        operation_metrics->latency->Observe(util::current_time(true) - start_time);
    }
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

    // The rest of the metrics are initialized after the backend opens, but this one has
    // to be here because it's possible it gets used by the open callback before Open()
    // fully returns.
    backends_opened_metric =
        telemetry_mgr->CounterInstance("zeek", "storage_backends_opened", {}, "Number of backends opened", "");
}

OperationResult Backend::Open(OpenResultCallback* cb, RecordValPtr options, TypePtr kt, TypePtr vt) {
    key_type = std::move(kt);
    val_type = std::move(vt);
    backend_options = options;

    forced_sync = options->GetField<BoolVal>("forced_sync")->Get();

    auto stype = options->GetField<EnumVal>("serializer");
    zeek::Tag stag{stype};

    auto s = storage_mgr->InstantiateSerializer(stag);
    if ( ! s )
        return {ReturnCode::INITIALIZATION_FAILED, s.error()};

    serializer = std::move(s.value());

    auto ret = DoOpen(cb, std::move(options));
    if ( ! ret.value )
        ret.value = cb->Backend();

    if ( ret.code == ReturnCode::SUCCESS )
        InitMetrics();

    // Complete sync callbacks to make sure the metrics get initialized plus that the
    // backend_opened event gets posted.
    if ( cb->IsSyncCallback() )
        CompleteCallback(cb, ret);

    return ret;
}

OperationResult Backend::Close(ResultCallback* cb) { return DoClose(cb); }

OperationResult Backend::Put(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite, double expiration_time) {
    cb->Init(put_metrics.get());

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

    auto ret = DoPut(cb, std::move(key), std::move(value), overwrite, expiration_time);
    if ( cb->IsSyncCallback() )
        cb->UpdateOperationMetrics(ret.code);

    return ret;
}

OperationResult Backend::Get(ResultCallback* cb, ValPtr key) {
    cb->Init(get_metrics.get());

    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCode::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    auto ret = DoGet(cb, std::move(key));
    if ( cb->IsSyncCallback() )
        cb->UpdateOperationMetrics(ret.code);

    return ret;
}

OperationResult Backend::Erase(ResultCallback* cb, ValPtr key) {
    cb->Init(erase_metrics.get());

    // See the note in Put().
    if ( ! same_type(key->GetType(), key_type) ) {
        auto ret = OperationResult{ReturnCode::KEY_TYPE_MISMATCH};
        CompleteCallback(cb, ret);
        return ret;
    }

    auto ret = DoErase(cb, std::move(key));
    if ( cb->IsSyncCallback() )
        cb->UpdateOperationMetrics(ret.code);

    return ret;
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

void Backend::EnqueueBackendOpened() {
    event_mgr.Enqueue(Storage::backend_opened, tag.AsVal(), backend_options);
    backends_opened_metric->Inc();
}

void Backend::EnqueueBackendLost(std::string_view reason) {
    event_mgr.Enqueue(Storage::backend_lost, tag.AsVal(), backend_options, make_intrusive<StringVal>(reason));
}

void Backend::InitMetrics() {
    if ( metrics_initialized )
        return;

    metrics_initialized = true;
    auto results_family =
        telemetry_mgr->CounterFamily("zeek", "storage_backend_operation_results",
                                     {"operation", "type", "config", "result"}, "Storage operation results");

    auto bounds_val = zeek::id::find_val<zeek::VectorVal>("Storage::latency_metric_bounds");
    std::vector<double> bounds(bounds_val->Size());
    for ( unsigned int i = 0; i < bounds_val->Size(); i++ )
        bounds[i] = bounds_val->DoubleAt(i);

    auto latency_family =
        telemetry_mgr->HistogramFamily("zeek", "storage_backend_operation_latency", {"operation", "type", "config"},
                                       bounds, "Storage Operation Latency", "seconds");

    std::string metrics_config = GetConfigMetricsLabel();
    put_metrics =
        std::make_unique<detail::OperationMetrics>(results_family, latency_family, "put", Tag(), metrics_config);
    get_metrics =
        std::make_unique<detail::OperationMetrics>(results_family, latency_family, "get", Tag(), metrics_config);
    erase_metrics =
        std::make_unique<detail::OperationMetrics>(results_family, latency_family, "erase", Tag(), metrics_config);

    bytes_read_metric = telemetry_mgr->CounterInstance("zeek", "storage_backend_data_written",
                                                       {{"type", Tag()}, {"config", metrics_config}},
                                                       "Storage data written to backend", "bytes");
    bytes_written_metric = telemetry_mgr->CounterInstance("zeek", "storage_backend_data_read",
                                                          {{"type", Tag()}, {"config", metrics_config}},
                                                          "Storage data read from backend", "bytes");

    expired_entries_metric = telemetry_mgr->CounterInstance("zeek", "storage_backend_expired_entries",
                                                            {{"type", Tag()}, {"config", metrics_config}},
                                                            "Storage expired entries removed by backend", "");
}

void Backend::IncBytesWrittenMetric(size_t written) { bytes_written_metric->Inc(written); }
void Backend::IncBytesReadMetric(size_t read) { bytes_read_metric->Inc(read); }
void Backend::IncExpiredEntriesMetric(size_t expired) { expired_entries_metric->Inc(expired); }

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
