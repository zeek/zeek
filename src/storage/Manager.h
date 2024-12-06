// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <mutex>

#include "zeek/Timer.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/storage/Backend.h"
#include "zeek/storage/Component.h"

namespace zeek::storage {

namespace detail {

class ExpireTimer final : public zeek::detail::Timer {
public:
    ExpireTimer(double t) : zeek::detail::Timer(t, zeek::detail::TIMER_STORAGE_EXPIRE) {}
    ~ExpireTimer() override {}
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
     * Opens a new storage backend.
     *
     * @param type The tag for the type of backend being opened.
     * @param config A record val representing the configuration for this
     * type of backend.
     * @param key_type The script-side type of the keys stored in the backend. Used for
     * validation of types.
     * @param val_type The script-side type of the values stored in the backend. Used for
     * validation of types and conversion during retrieval.
     * @return A pair containing a pointer to a backend and a string for
     * returning error messages if needed.
     */
    BackendResult OpenBackend(const Tag& type, RecordValPtr configuration, TypePtr key_type, TypePtr val_type);

    /**
     * Closes a storage backend.
     */
    void CloseBackend(BackendPtr backend);

protected:
    friend class storage::detail::ExpireTimer;
    void Expire();
    void StartExpireTimer();

private:
    std::vector<BackendPtr> backends;
    std::mutex backends_mtx;
};

} // namespace zeek::storage

namespace zeek {

extern storage::Manager* storage_mgr;

} // namespace zeek
