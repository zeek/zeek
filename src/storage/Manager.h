// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <mutex>
#include <thread>

#include "zeek/3rdparty/jthread.hpp"
#include "zeek/Timer.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/storage/Backend.h"
#include "zeek/storage/Component.h"

namespace zeek::storage {

namespace detail {

class ExpirationTimer final : public zeek::detail::Timer {
public:
    ExpirationTimer(double t) : zeek::detail::Timer(t, zeek::detail::TIMER_STORAGE_EXPIRE) {}
    ~ExpirationTimer() override {}
    void Dispatch(double t, bool is_expire) override;
};

} // namespace detail

class Manager final : public plugin::ComponentManager<Component> {
public:
    Manager();
    ~Manager();

    /**
     * Initialization of the manager. This is called late during Zeek's
     * initialization after any scripts are processed.
     */
    void InitPostScript();

    /**
     * Instantiates a new backend object. The backend will be in a closed state,
     * and OpenBackend() will need to be called to fully initialize it.
     *
     * @param type The tag for the type of backend being opened.
     * @return A std::expected containing either a valid BackendPtr with the
     * result of the operation or a string containing an error message for
     * failure.
     */
    zeek::expected<BackendPtr, std::string> Instantiate(const Tag& type);

    /**
     * Opens a new storage backend.
     *
     * @param backend The backend object to open.
     * @param options A record val representing the configuration for this type of
     * backend.
     * @param key_type The script-side type of the keys stored in the backend. Used for
     * validation of types.
     * @param val_type The script-side type of the values stored in the backend. Used for
     * validation of types and conversion during retrieval.
     * @param cb An optional callback object if being called via an async context.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult OpenBackend(BackendPtr backend, OpenResultCallback* cb, RecordValPtr options, TypePtr key_type,
                                TypePtr val_type);

    /**
     * Closes a storage backend.
     *
     * @param backend A pointer to the backend being closed.
     * @param cb An optional callback object if being called via an async context.
     * @return A struct describing the result of the operation, containing a code, an
     * optional error string, and a ValPtr for operations that return values.
     */
    OperationResult CloseBackend(BackendPtr backend, OperationResultCallback* cb);

    void Expire();

protected:
    friend class storage::detail::ExpirationTimer;
    void RunExpireThread();
    void StartExpirationTimer();
    std::jthread expiration_thread;

    friend class storage::OpenResultCallback;
    void RegisterBackend(BackendPtr backend);

private:
    std::vector<BackendPtr> backends;
    std::mutex backends_mtx;
};

} // namespace zeek::storage

namespace zeek {

extern storage::Manager* storage_mgr;

} // namespace zeek
