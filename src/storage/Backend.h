// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/OpaqueVal.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/storage/Serializer.h"

namespace zeek::detail::trigger {
class Trigger;
using TriggerPtr = IntrusivePtr<Trigger>;
} // namespace zeek::detail::trigger

namespace zeek::telemetry {
class Counter;
using CounterPtr = std::shared_ptr<Counter>;
class CounterFamily;
using CounterFamilyPtr = std::shared_ptr<CounterFamily>;
class Histogram;
using HistogramPtr = std::shared_ptr<Histogram>;
class HistogramFamily;
using HistogramFamilyPtr = std::shared_ptr<HistogramFamily>;
} // namespace zeek::telemetry

namespace zeek::storage {

namespace detail {
struct OperationMetrics {
    telemetry::CounterPtr success;
    telemetry::CounterPtr fail;
    telemetry::CounterPtr error;
    telemetry::CounterPtr timeouts;
    telemetry::HistogramPtr latency;

    OperationMetrics(const telemetry::CounterFamilyPtr& results_family,
                     const telemetry::HistogramFamilyPtr& latency_family, std::string_view operation_type,
                     std::string_view backend_type, std::string_view backend_config);
};
} // namespace detail

class Manager;

/**
 * A structure mapped to the script-level Storage::OperationResult type for returning
 * status from storage operations.
 */
struct OperationResult {
    /**
     * One of a set of return values used to return a code-based status. The default set
     * of these values is automatically looked up by the `ReturnCode` class, but
     * additional codes may be added by backends. See the script-level
     * `Storage::ReturnCode` enum for documentation for the default available statuses.
     */
    EnumValPtr code;

    /**
     * An optional error string that can be passed in the result in the case of failure.
     */
    std::string err_str;

    /**
     * A generic value pointer for operations that can return values, such as `Open()` and
     * `Get()`.
     */
    ValPtr value;

    /**
     * Returns a RecordVal of the script-level type `Storage::OperationResult` from the
     * values stored.
     */
    RecordValPtr BuildVal();

    /**
     * Static version of `BuildVal()` that returns a RecordVal of the script-level type
     * `Storage::OperationResult` from the values provided.
     */
    static RecordValPtr MakeVal(EnumValPtr code, std::string_view err_str = "", ValPtr value = nullptr);
};

/**
 * Base callback object for asynchronous operations.
 */
class ResultCallback {
public:
    ResultCallback() = default;
    ResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc);
    virtual ~ResultCallback() = default;

    /**
     * Called on the callback when an operation times out. Sets the resulting status to
     * TIMEOUT and times out the trigger.
     */
    void Timeout();

    /**
     * Returns whether the callback was created in an async context. This can be used to
     * determine whether an operation was called synchronously or asynchronously.
     */
    bool IsSyncCallback() const { return ! trigger; }

    /**
     * Completes a callback, releasing the trigger if it was valid or storing the result
     * for later usage if needed.
     */
    virtual void Complete(OperationResult res);

    OperationResult Result() const { return result; }

    /**
     * Stores the collection of metrics instruments to update when the operation completes
     * and sets the start time for an operation to be used to update the latency metric
     * when the operation completes. This is unset for open/close callbacks.
     */
    void Init(detail::OperationMetrics* m);

    /**
     * Update the metrics based on a return value.
     */
    void UpdateOperationMetrics(EnumValPtr c);

    /**
     * Stores the amount of data transferred in the operation. This can be used by async
     * backends to set the amount transferred in Put operations so it can be added to the
     * metrics when the operation finishes.
     */
    void AddDataTransferredSize(size_t size) { transferred_size += size; }

    /**
     * Returns the amount of data transferred in this operation.
     */
    size_t GetDataTransferredSize() const { return transferred_size; }

protected:
    zeek::detail::trigger::TriggerPtr trigger;
    const void* assoc = nullptr;
    OperationResult result;
    detail::OperationMetrics* operation_metrics = nullptr;
    double start_time = 0.0;
    size_t transferred_size = 0;
};

class OpenResultCallback;

/**
 * A list of available modes that backends can support. A combination of these is passed
 * to `Backend::Backend` during plugin initialization.
 */
enum SupportedModes : uint8_t { SYNC = 0x01, ASYNC = 0x02 };

class Backend : public zeek::Obj {
public:
    /**
     * Returns a descriptive tag representing the source for debugging.
     */
    const char* Tag() const { return tag_str.c_str(); }

    /**
     * Store a new key/value pair in the backend.
     *
     * @param cb A callback object for returning status if being called via an async
     * context.
     * @param key the key for the data being inserted.
     * @param value the value for the data being inserted.
     * @param overwrite whether an existing value for a key should be overwritten.
     * @param expiration_time the time when this entry should be automatically
     * removed. Set to zero to disable expiration. This time is based on the current network
     * time.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult Put(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite = true,
                        double expiration_time = 0);

    /**
     * Retrieve a value from the backend for a provided key.
     *
     * @param cb A callback object for returning status if being called via an async
     * context.
     * @param key the key to lookup in the backend.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult Get(ResultCallback* cb, ValPtr key);

    /**
     * Erases the value for a key from the backend.
     *
     * @param cb A callback object for returning status if being called via an async
     * context.
     * @param key the key to erase
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult Erase(ResultCallback* cb, ValPtr key);

    /**
     * Returns whether the backend is opened.
     */
    virtual bool IsOpen() = 0;

    bool SupportsSync() const { return (modes & SupportedModes::SYNC) == SupportedModes::SYNC; }
    bool SupportsAsync() const { return (modes & SupportedModes::ASYNC) == SupportedModes::ASYNC; }

    /**
     * Optional method to allow a backend to poll for data. This can be used to
     * mimic sync mode even if the backend only supports async.
     */
    void Poll() { DoPoll(); }

    /**
     * Returns the options record that was passed to `Manager::OpenBackend` when the
     * backend was opened.
     */
    const RecordValPtr& Options() const { return backend_options; }

    /**
     * Returns the state of the forced_sync option that was passed in the options record to Open().
     */
    bool IsForcedSync() const { return forced_sync; }

protected:
    // Allow the manager to call Open/Close.
    friend class storage::Manager;

    // Allow OpenResultCallback to call EnqueueConnectionEstablished.
    friend class storage::OpenResultCallback;

    /**
     * Constructor
     *
     * @param modes A combination of values from SupportedModes. These modes
     # define whether a backend only supports sync or async or both.
     * @param tag The name of the plugin that this backend is part of. It
     * should match the string sent in the ``Plugin`` code for the backend
     * plugin.
     */
    Backend(uint8_t modes, std::string_view tag_name);

    /**
     * Called by the manager system to open the backend.
     *
     * @param cb A callback object for returning status if being called via an async
     * context.
     * @param options A record storing configuration options for the backend.
     * @param kt The script-side type of the keys stored in the backend. Used for
     * validation of types.
     * @param vt The script-side type of the values stored in the backend. Used for
     * validation of types and conversion during retrieval.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult Open(OpenResultCallback* cb, RecordValPtr options, TypePtr kt, TypePtr vt);

    /**
     * Finalizes the backend when it's being closed.
     *
     * @param cb A callback object for returning status if being called via an async
     * context.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult Close(ResultCallback* cb);

    /**
     * Removes any entries in the backend that have expired. Can be overridden by
     * derived classes.
     *
     * @param current_network_time The network time as of the start of the
     * expiration operation.
     */
    void Expire(double current_network_time) { DoExpire(current_network_time); }

    /**
     * Enqueues the Storage::backend_opened event. This is called automatically
     * when an OpenResultCallback is completed successfully.
     */
    void EnqueueBackendOpened();

    /**
     * Enqueues the Storage::backend_lost event with an optional reason
     * string. This should be called by the backends whenever they lose their
     * connection.
     */
    void EnqueueBackendLost(std::string_view reason);

    /**
     * Completes a callback and cleans up the memory if the callback was from a sync
     * context. This should be called by backends instead of calling the callback's
     * \a`Complete` method directly.
     */
    void CompleteCallback(ResultCallback* cb, const OperationResult& data) const;

    /**
     * Returns a string compatible with Prometheus that's used as a tag to differentiate
     * entries of backend instances.
     */
    std::string GetConfigMetricsLabel() const { return DoGetConfigMetricsLabel(); }

    /**
     * Utility method to increase the metrics for number of bytes written by a backend.
     *
     * @param written The number of bytes written by the last operation.
     */
    void IncBytesWrittenMetric(size_t written);

    /**
     * Utility method to increase the metrics for number of bytes read by a backend.
     *
     * @param read The number of bytes read by the last operation.
     */
    void IncBytesReadMetric(size_t read);

    /**
     * Utility method to increase the metrics for number of entries expired and removed
     * from the backend.
     *
     * @param expired The number of elements removed by the last operation.
     */
    void IncExpiredEntriesMetric(size_t expired);

    TypePtr key_type;
    TypePtr val_type;
    RecordValPtr backend_options;

    zeek::Tag tag;
    std::string tag_str;
    std::unique_ptr<Serializer> serializer;

private:
    /**
     * Workhorse method for calls to `Manager::OpenBackend()`. See that method for
     * documentation of the arguments. This must be overridden by all backends.
     */
    virtual OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) = 0;

    /**
     * Workhorse method for calls to `Manager::CloseBackend()`. See that method for
     * documentation of the arguments. This must be overridden by all backends.
     */
    virtual OperationResult DoClose(ResultCallback* cb) = 0;

    /**
     * Workhorse method for calls to `Backend::Put()`. See that method for
     * documentation of the arguments. This must be overridden by all backends.
     */
    virtual OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                                  double expiration_time) = 0;

    /**
     * Workhorse method for calls to `Backend::Get()`. See that method for
     * documentation of the arguments. This must be overridden by all backends.
     */
    virtual OperationResult DoGet(ResultCallback* cb, ValPtr key) = 0;

    /**
     * Workhorse method for calls to `Backend::Erase()`. See that method for
     * documentation of the arguments. This must be overridden by all backends.
     */
    virtual OperationResult DoErase(ResultCallback* cb, ValPtr key) = 0;

    /**
     * Optional method for backends to override to provide direct polling. This should be
     * implemented to support synchronous operations on backends that only provide
     * asynchronous communication. See the built-in Redis backend for an example.
     */
    virtual void DoPoll() {}

    /**
     * Optional method for backends to override to provide non-native expiration of
     * items. This is called by the manager on a timer. This can also be used to implement
     * expiration when reading packet captures.
     *
     * @param current_network_time The current network time at which expiration is
     * happening.
     */
    virtual void DoExpire(double current_network_time) {}

    /**
     * Returns a string compatible with Prometheus that's used as a tag to differentiate
     * entries of backend instances.
     */
    virtual std::string DoGetConfigMetricsLabel() const = 0;

    /**
     * Initializes the instruments for various storage metrics.
     */
    void InitMetrics();

    uint8_t modes;
    bool forced_sync = false;
    bool metrics_initialized = false;

    // These are owned by the backend but are passed into the callbacks to be
    // updated when those complete/timeout.
    std::unique_ptr<detail::OperationMetrics> put_metrics;
    std::unique_ptr<detail::OperationMetrics> get_metrics;
    std::unique_ptr<detail::OperationMetrics> erase_metrics;

    telemetry::CounterPtr bytes_written_metric;
    telemetry::CounterPtr bytes_read_metric;
    telemetry::CounterPtr backends_opened_metric;
    telemetry::CounterPtr expired_entries_metric;
};

using BackendPtr = zeek::IntrusivePtr<Backend>;

namespace detail {

extern OpaqueTypePtr backend_opaque;

/**
 * OpaqueVal interface for returning BackendHandle objects to script-land.
 */
class BackendHandleVal : public OpaqueVal {
public:
    BackendHandleVal() : OpaqueVal(detail::backend_opaque) {}
    BackendHandleVal(BackendPtr backend) : OpaqueVal(detail::backend_opaque), backend(std::move(backend)) {}
    ~BackendHandleVal() override = default;

    /**
     * Attempts to cast a handle passed from script-land into a BackendHandleVal. Used by
     * various BIF methods.
     *
     * @param handle The handle passed from script-land.
     * @return A zeek::expected with either the correctly-casted handle, or an OperationResult
     * containing error information.
     */
    static zeek::expected<storage::detail::BackendHandleVal*, OperationResult> CastFromAny(Val*);

    BackendPtr backend;

protected:
    IntrusivePtr<Val> DoClone(CloneState* state) override { return {NewRef{}, this}; }

    DECLARE_OPAQUE_VALUE_DATA(BackendHandleVal)
};

} // namespace detail

/**
 * A specialized version of callback for returning from `open` operations. This returns a
 * `BackendHandleVal` in the `value` field of the result when successful.
 */
class OpenResultCallback : public ResultCallback {
public:
    OpenResultCallback(IntrusivePtr<detail::BackendHandleVal> backend);
    OpenResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc,
                       IntrusivePtr<detail::BackendHandleVal> backend);
    void Complete(OperationResult res) override;

    IntrusivePtr<detail::BackendHandleVal> Backend() const { return backend; }

private:
    IntrusivePtr<detail::BackendHandleVal> backend;
};

} // namespace zeek::storage
