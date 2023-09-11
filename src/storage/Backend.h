// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/OpaqueVal.h"
#include "zeek/Val.h"

namespace zeek::storage {

// Result from storage operations that return a simple pass/fail. The bool value
// is whether the operation succeeded, and the string value is an error message
// if the operation failed.
using BoolResult = std::pair<bool, std::string>;

// Result from storage operations that return Vals. The ValPtr is an
// IntrusivePtr to some result, and can be null if the operation failed. The
// string value will store an error message if the result is null.
using ValResult = std::pair<ValPtr, std::string>;

namespace detail {

extern OpaqueTypePtr backend_opaque;

}

class Backend : public zeek::Obj {
public:
    Backend() = default;

    /**
     * Called by the manager system to open the backend.
     *
     * @param config A record type storing configuration options for the backend.
     * @param vt The script-land type to be used when retrieving values back from
     * the store. This should be stored in the val_type member variable.
     * @return true if the backend could be opened, false otherwise.
     */
    bool Open(RecordValPtr config, TypePtr vt);

    /**
     * Finalizes the backend when it's being closed. Can be overridden by
     * derived classes.
     */
    virtual void Done() {}

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * Must be overridden by derived classes.
     *
     * @return The debugging name.
     */
    virtual const char* Tag() = 0;

    /**
     * Store a new key/value pair in the backend.
     *
     * @param key the key for the pair
     * @param value the value for the pair
     * @param overwrite whether an existing value for a key should be overwritten.
     * @return A result pair containing a bool with the success state, and a possible
     * error string if the operation failed.
     */
    BoolResult Store(ValPtr key, ValPtr value, bool overwrite = true);

    /**
     * Retrieve a value from the backend for a provided key.
     *
     * @param key the key to lookup in the backend.
     * @return A result pair containing a ValPtr with the resulting value or nullptr
     * retrieval failed, and a string with the error message if the operation failed.
     */
    ValResult Retrieve(ValPtr key);

    /**
     * Erases the value for a key from the backend.
     *
     * @return A result pair containing a bool with the success state, and a possible
     * error string if the operation failed.
     */
    BoolResult Erase(ValPtr key);

    /**
     * Returns whether the backend is opened.
     */
    virtual bool IsOpen() = 0;

    const TypePtr ValueType() const { return val_type; }

    // QUESTIONS
    // Should init method allow for local worker connections vs aggregation?

protected:
    /**
     * The workhorse method for Open().
     */
    virtual bool DoOpen(RecordValPtr config, TypePtr vt) = 0;

    /**
     * The workhorse method for Store().
     */
    virtual BoolResult DoStore(ValPtr key, ValPtr value, bool overwrite = true) = 0;

    /**
     * The workhorse method for Retrieve().
     */
    virtual ValResult DoRetrieve(ValPtr key) = 0;

    /**
     * The workhorse method for Erase().
     */
    virtual BoolResult DoErase(ValPtr key) = 0;

    // The script-land type for values stored in the backend. This is provided as
    // part of the Open() arguments.
    TypePtr val_type;
};

using BackendPtr = zeek::IntrusivePtr<Backend>;

class BackendHandleVal : public OpaqueVal {
public:
    BackendHandleVal() : OpaqueVal(detail::backend_opaque) {}
    BackendHandleVal(BackendPtr backend) : OpaqueVal(detail::backend_opaque), backend(std::move(backend)) {}

    ~BackendHandleVal() override = default;

    void ValDescribe(ODesc* d) const override {}

    const char* OpaqueName() const override { return "BackendHandleVal"; }

    BackendPtr backend;
};

} // namespace zeek::storage
