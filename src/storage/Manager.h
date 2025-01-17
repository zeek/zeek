// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <mutex>

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
    ~Manager() = default;

    /**
     * Initialization of the manager. This is called late during Zeek's
     * initialization after any scripts are processed.
     */
    void InitPostScript();

    /**
     * Instantiates a new backend object. The backend will be in a closed state, and OpenBackend()
     * will need to be called to fully initialize it.
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
     * @return An optional value potentially containing an error string if needed. Will be
     * unset if the operation succeeded.
     */
    ErrorResult OpenBackend(BackendPtr backend, RecordValPtr options, TypePtr key_type, TypePtr val_type,
                            OpenResultCallback* cb = nullptr);

    /**
     * Closes a storage backend.
     */
    ErrorResult CloseBackend(BackendPtr backend, ErrorResultCallback* cb = nullptr);

protected:
    friend class storage::detail::ExpirationTimer;
    void Expire();
    void StartExpirationTimer();

    friend class storage::OpenResultCallback;
    void AddBackendToMap(BackendPtr backend);

private:
    std::vector<BackendPtr> backends;
    std::mutex backends_mtx;
};

} // namespace zeek::storage

namespace zeek {

extern storage::Manager* storage_mgr;

} // namespace zeek
