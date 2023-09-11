// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/OpaqueVal.h"
#include "zeek/Val.h"
#include "zeek/util.h"

namespace zeek::storage {

class Manager;

// Result from storage operations that may return an error message. If the
// optional value is unset, the operation succeeded.
using ErrorResult = std::optional<std::string>;

// Result from storage operations that return Vals. The ValPtr is an
// IntrusivePtr to some result, and can be null if the operation failed. The
// string value will store an error message if the result is null.
using ValResult = zeek::expected<ValPtr, std::string>;

class Backend : public zeek::Obj {
public:
    /**
     * Returns a descriptive tag representing the source for debugging.
     */
    const char* Tag() { return tag.c_str(); }

    /**
     * Store a new key/value pair in the backend.
     *
     * @param key the key for the pair
     * @param value the value for the pair
     * @param overwrite whether an existing value for a key should be overwritten.
     * @return A result pair containing a bool with the success state, and a
     * possible error string if the operation failed.
     */
    ErrorResult Put(ValPtr key, ValPtr value, bool overwrite = true);

    /**
     * Retrieve a value from the backend for a provided key.
     *
     * @param key the key to lookup in the backend.
     * @param value_type The script-land type to be used when retrieving values
     * from the backend.
     * @return A result pair containing a ValPtr with the resulting value or
     * nullptr retrieval failed, and a string with the error message if the
     * operation failed.
     */
    ValResult Get(ValPtr key, TypePtr value_type);

    /**
     * Erases the value for a key from the backend.
     *
     * @return An optional value potentially containing an error string if
     * needed. Will be unset if the operation succeeded.
     * possible error string if the operation failed.
     */
    ErrorResult Erase(ValPtr key);

    /**
     * Returns whether the backend is opened.
     */
    virtual bool IsOpen() = 0;

protected:
    // Allow the manager to call Open/Close.
    friend class storage::Manager;

    /**
     * Constructor
     *
     * @param tag A string representation of the tag for this backend. This
     * is passed from the Manager through the component factory.
     */
    Backend(std::string_view tag) : tag(tag) {}

    /**
     * Called by the manager system to open the backend.
     *
     * @param options A record storing configuration options for the backend.
     * @return A result pair containing a bool with the success state, and a
     * possible error string if the operation failed.
     */
    ErrorResult Open(RecordValPtr options);

    /**
     * Finalizes the backend when it's being closed. Can be overridden by
     * derived classes.
     */
    virtual void Close() {}

    /**
     * The workhorse method for Open().
     */
    virtual ErrorResult DoOpen(RecordValPtr options) = 0;

    /**
     * The workhorse method for Put().
     */
    virtual ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true) = 0;

    /**
     * The workhorse method for Get().
     */
    virtual ValResult DoGet(ValPtr key, TypePtr vt) = 0;

    /**
     * The workhorse method for Erase().
     */
    virtual ErrorResult DoErase(ValPtr key) = 0;

    std::string tag;
};

using BackendPtr = zeek::IntrusivePtr<Backend>;

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
} // namespace zeek::storage
