// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IntrusivePtr.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Val.h"
#include "zeek/util.h"

namespace zeek::detail::trigger {
class Trigger;
using TriggerPtr = IntrusivePtr<Trigger>;
} // namespace zeek::detail::trigger

namespace zeek::storage {

class Manager;

// Base callback object for async operations. This is just here to allow some code reuse
// in the other callback methods.
class ResultCallback {
public:
    ResultCallback() = default;
    ResultCallback(detail::trigger::TriggerPtr trigger, const void* assoc);
    virtual ~ResultCallback() = default;
    void Timeout();
    bool SyncCallback() const { return ! trigger; }

protected:
    void CompleteWithVal(Val* result);

    IntrusivePtr<zeek::detail::trigger::Trigger> trigger;
    const void* assoc = nullptr;
};

struct OperationResult {
    EnumValPtr code;
    std::string err_str;
    ValPtr value;

    void FillRecordVal(const RecordValPtr& rec);
};

class OperationResultCallback : public ResultCallback {
public:
    OperationResultCallback() = default;
    OperationResultCallback(detail::trigger::TriggerPtr trigger, const void* assoc);
    void Complete(const OperationResult& res);
    OperationResult Result() { return result; }

private:
    OperationResult result;
};

class OpenResultCallback;

enum SupportedModes : uint8_t { SYNC = 0x01, ASYNC = 0x02 };

class Backend : public zeek::Obj {
public:
    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * @return The debugging name.
     */
    virtual const char* Tag() = 0;

    /**
     * Store a new key/value pair in the backend.
     *
     * @param key the key for the pair.
     * @param value the value for the pair.
     * @param overwrite whether an existing value for a key should be overwritten.
     * @param expiration_time the time when this entry should be automatically
     * removed. Set to zero to disable expiration. This time is based on the current network
     * time.
     * @param cb An optional callback object if being called via an async context.
     */
    OperationResult Put(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                        OperationResultCallback* cb = nullptr);

    /**
     * Retrieve a value from the backend for a provided key.
     *
     * @param key the key to lookup in the backend.
     * @param cb An optional callback object if being called via an async context.
     */
    OperationResult Get(ValPtr key, OperationResultCallback* cb = nullptr);

    /**
     * Erases the value for a key from the backend.
     *
     * @param key the key to erase
     * @param cb An optional callback object if being called via an async context.
     */
    OperationResult Erase(ValPtr key, OperationResultCallback* cb = nullptr);

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
    virtual void Poll() {}

    const RecordValPtr& Options() const { return backend_options; }

protected:
    // Allow the manager to call Open/Done.
    friend class storage::Manager;

    // Allow OpenResultCallback to call PostConnectionEstablished.
    friend class storage::OpenResultCallback;

    /**
     * Constructor
     *
     * @param modes A combination of values from SupportedModes. These modes
     # define whether a backend only supports sync or async or both.
     */
    Backend(uint8_t modes) : modes(modes) {}

    /**
     * Called by the manager system to open the backend.
     *
     * @param options A record storing configuration options for the backend.
     * @param kt The script-side type of the keys stored in the backend. Used for
     * validation of types.
     * @param vt The script-side type of the values stored in the backend. Used for
     * validation of types and conversion during retrieval.
     * @param cb An optional callback object if being called via an async context.
     */
    OperationResult Open(RecordValPtr options, TypePtr kt, TypePtr vt, OpenResultCallback* cb = nullptr);

    /**
     * Finalizes the backend when it's being closed.
     *
     * @param cb An optional callback object if being called via an async context.
     */
    OperationResult Done(OperationResultCallback* cb = nullptr);

    /**
     * The workhorse method for Open().
     */
    virtual OperationResult DoOpen(RecordValPtr options, OpenResultCallback* cb = nullptr) = 0;

    /**
     * The workhorse method for Done().
     */
    virtual OperationResult DoDone(OperationResultCallback* cb = nullptr) = 0;

    /**
     * The workhorse method for Put().
     */
    virtual OperationResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                                  OperationResultCallback* cb = nullptr) = 0;

    /**
     * The workhorse method for Get().
     */
    virtual OperationResult DoGet(ValPtr key, OperationResultCallback* cb = nullptr) = 0;

    /**
     * The workhorse method for Erase().
     */
    virtual OperationResult DoErase(ValPtr key, OperationResultCallback* cb = nullptr) = 0;

    /**
     * Removes any entries in the backend that have expired. Can be overridden by
     * derived classes.
     */
    virtual void Expire() {}

    /**
     * Posts the Storage::connection_established event. This is called
     * automatically when an OpenResultCallback is completed successfully.
     */
    void PostConnectionEstablished();

    /**
     * Posts the Storage::connection_lost event with an optional reason string.
     * string. This should be called by the backends whenever they lose their
     * connection.
     */
    void PostConnectionLost(std::string_view reason);

    TypePtr key_type;
    TypePtr val_type;
    RecordValPtr backend_options;

protected:
    void CompleteCallback(OpenResultCallback* cb, const OperationResult& data) const;
    void CompleteCallback(OperationResultCallback* cb, const OperationResult& data) const;

private:
    uint8_t modes;
};

using BackendPtr = zeek::IntrusivePtr<Backend>;

// Result from calls to open a new backend. The value will be set if the open
// operation succeeded, and the string value is an error message if the
// operation failed. This isn't used by the backends themselves, but by the
// Manager to return error messages to callers if necessary (notably BIFs).
using BackendResult = zeek::expected<BackendPtr, std::string>;

namespace detail {

extern OpaqueTypePtr backend_opaque;

class BackendHandleVal : public OpaqueVal {
public:
    BackendHandleVal() : OpaqueVal(detail::backend_opaque) {}
    BackendHandleVal(BackendPtr backend) : OpaqueVal(detail::backend_opaque), backend(std::move(backend)) {}
    ~BackendHandleVal() override = default;

    BackendPtr backend;

protected:
    IntrusivePtr<Val> DoClone(CloneState* state) override { return {NewRef{}, this}; }

    DECLARE_OPAQUE_VALUE_DATA(BackendHandleVal)
};

} // namespace detail

// A callback for the Backend::Open() method that returns an error or a backend handle.
class OpenResultCallback : public ResultCallback {
public:
    OpenResultCallback(IntrusivePtr<detail::BackendHandleVal> backend);
    OpenResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc,
                       IntrusivePtr<detail::BackendHandleVal> backend);
    void Complete(const OperationResult& res);

    OperationResult Result() const { return result; }
    IntrusivePtr<detail::BackendHandleVal> Backend() const { return backend; }

private:
    OperationResult result{};
    IntrusivePtr<detail::BackendHandleVal> backend;
};

} // namespace zeek::storage
