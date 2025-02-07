// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

#include <atomic>

#include "zeek/Desc.h"
#include "zeek/RunState.h"

#include "const.bif.netvar_h"

std::atomic_flag expire_running;

namespace zeek::storage {

void detail::ExpirationTimer::Dispatch(double t, bool is_expire) {
    if ( is_expire )
        return;

    // If there isn't an active thread, spin up a new one. Expiration may take
    // some time to complete and we want it to get all the way done before we
    // start another one running. If this causes us to skip a cycle, that's not
    // a big deal as the next cycle will catch anything that should be expired
    // in the interim.
    if ( ! expire_running.test_and_set() ) {
        DBG_LOG(DBG_STORAGE, "Starting new expiration thread");
        storage_mgr->expiration_thread = std::jthread([]() { storage_mgr->Expire(); });
    }

    storage_mgr->StartExpirationTimer();
}

Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") {}

void Manager::InitPostScript() {
    detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend");
    StartExpirationTimer();
}

zeek::expected<BackendPtr, std::string> Manager::Instantiate(const Tag& type) {
    Component* c = Lookup(type);
    if ( ! c ) {
        return zeek::unexpected<std::string>(
            util::fmt("Request to open unknown backend (%d:%d)", type.Type(), type.Subtype()));
    }

    if ( ! c->Factory() ) {
        return zeek::unexpected<std::string>(
            util::fmt("Factory invalid for backend %s", GetComponentName(type).c_str()));
    }

    ODesc d;
    type.AsVal()->Describe(&d);

    BackendPtr bp = c->Factory()(d.Description());

    if ( ! bp ) {
        return zeek::unexpected<std::string>(
            util::fmt("Failed to instantiate backend %s", GetComponentName(type).c_str()));
    }

    return bp;
}

ErrorResult Manager::OpenBackend(BackendPtr backend, RecordValPtr options, TypePtr key_type, TypePtr val_type,
                                 OpenResultCallback* cb) {
    if ( auto res = backend->Open(std::move(options), std::move(key_type), std::move(val_type), cb); res.has_value() ) {
        return util::fmt("Failed to open backend %s: %s", backend->Tag(), res.value().c_str());
    }

    RegisterBackend(std::move(backend));

    // TODO: post Storage::backend_opened event

    return std::nullopt;
}

ErrorResult Manager::CloseBackend(BackendPtr backend, ErrorResultCallback* cb) {
    // Expiration runs on a separate thread and loops over the vector of backends. The mutex
    // here ensures exclusive access. This one happens in a block because we can remove the
    // backend from the vector before actually closing it.
    {
        std::unique_lock<std::mutex> lk(backends_mtx);
        auto it = std::find(backends.begin(), backends.end(), backend);
        if ( it != backends.end() )
            backends.erase(it);
    }

    if ( auto res = backend->Close(cb); res.has_value() ) {
        return util::fmt("Failed to close backend %s: %s", backend->Tag(), res.value().c_str());
    }

    return std::nullopt;

    // TODO: post Storage::backend_lost event
}

void Manager::Expire() {
    // Expiration runs on a separate thread and loops over the vector of backends. The mutex
    // here ensures exclusive access.
    std::unique_lock<std::mutex> lk(backends_mtx);

    DBG_LOG(DBG_STORAGE, "Expiration running, have %zu backends to check", backends.size());

    for ( auto it = backends.begin(); it != backends.end() && ! run_state::terminating; ++it ) {
        if ( (*it)->IsOpen() )
            (*it)->Expire();
    }

    expire_running.clear();
}

void Manager::StartExpirationTimer() {
    zeek::detail::timer_mgr->Add(
        new detail::ExpirationTimer(run_state::network_time + zeek::BifConst::Storage::expire_interval));
    DBG_LOG(DBG_STORAGE, "Next expiration check at %f",
            run_state::network_time + zeek::BifConst::Storage::expire_interval);
}

void Manager::RegisterBackend(BackendPtr backend) {
    // Expiration runs on a separate thread and loops over the vector of backends. The mutex
    // here ensures exclusive access.
    std::unique_lock<std::mutex> lk(backends_mtx);

    backends.push_back(std::move(backend));
    DBG_LOG(DBG_STORAGE, "Registered backends: %zu", backends.size());
}

} // namespace zeek::storage
