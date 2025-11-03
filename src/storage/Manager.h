// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <mutex>

// Apple's clang has an implementation of std::jthread, but it's still marked
// as experimental. Use the 3rdparty one for that platform and for any other
// that doesn't have it. This could move to util.h if some other code needs
// jthread in the future.
#if defined(__APPLE__) || ! defined(__cpp_lib_jthread)
#include "zeek/3rdparty/jthread.hpp"
namespace zeek {
using jthread = nonstd::jthread;
}
#else
#include <thread>
namespace zeek {
using jthread = std::jthread;
}
#endif

#include "zeek/Timer.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/storage/Backend.h"
#include "zeek/storage/Component.h"
#include "zeek/storage/Serializer.h"

namespace zeek::storage {

namespace detail {

class ExpirationTimer final : public zeek::detail::Timer {
public:
    ExpirationTimer(double t) : zeek::detail::Timer(t, zeek::detail::TIMER_STORAGE_EXPIRE) {}
    void Dispatch(double t, bool is_expire) override;
};

} // namespace detail

class Manager final {
public:
    Manager();
    ~Manager();

    /**
     * Initialization of the manager. This is called late during Zeek's initialization
     * after any scripts are processed.
     */
    void InitPostScript();

    /**
     * Instantiates a new backend object. The backend will be in a closed state, and
     * OpenBackend() will need to be called to fully initialize it.
     *
     * @param type The tag for the type of backend being opened.
     * @return A std::expected containing either a valid BackendPtr with the result of the
     * operation or a string containing an error message for failure.
     */
    zeek::expected<BackendPtr, std::string> InstantiateBackend(const Tag& type);

    /**
     * Instantiates a new serializer object.
     *
     * @param type The tag for the type of backend being opened.
     * @return A std::expected containing either a valid BackendPtr with the result of the
     * operation or a string containing an error message for failure.
     */
    zeek::expected<std::unique_ptr<Serializer>, std::string> InstantiateSerializer(const Tag& type);

    /**
     * Opens a new storage backend.
     *
     * @param backend The backend object to open.
     * @param cb A callback object for returning status if being called via an async
     * context.
     * @param key_type The script-side type of the keys stored in the backend. Used for
     * validation of types for `key` arguments during all operations.
     * @param val_type The script-side type of the values stored in the backend. Used for
     * validation of types for `put` operations and type conversion during `get`
     * operations.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult OpenBackend(BackendPtr backend, OpenResultCallback* cb, RecordValPtr options, TypePtr key_type,
                                TypePtr val_type);

    /**
     * Closes a storage backend.
     *
     * @param backend A pointer to the backend being closed.
     * @param cb A callback object for returning status if being called via an async
     * context.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult CloseBackend(BackendPtr backend, ResultCallback* cb);

    /**
     * Runs an expire operation on all open backends. This is called by the expiration
     * timer and shouldn't be called directly otherwise, since it should only happen on a
     * separate thread.
     *
     * @param t The network time that the expiration started.
     */
    void Expire(double t);

    plugin::ComponentManager<BackendComponent>& BackendMgr() { return backend_mgr; }
    plugin::ComponentManager<SerializerComponent>& SerializerMgr() { return serializer_mgr; }

protected:
    friend class storage::detail::ExpirationTimer;
    void RunExpireThread();
    void StartExpirationTimer();
    size_t BackendCount();
    zeek::jthread expiration_thread;

    friend class storage::OpenResultCallback;
    void RegisterBackend(BackendPtr backend);

private:
    std::vector<BackendPtr> backends;
    std::mutex backends_mtx;

    plugin::ComponentManager<BackendComponent> backend_mgr;
    plugin::ComponentManager<SerializerComponent> serializer_mgr;
};

} // namespace zeek::storage

namespace zeek {

extern storage::Manager* storage_mgr;

} // namespace zeek
