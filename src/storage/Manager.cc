// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

#include "const.bif.netvar_h"

namespace zeek::storage {

void detail::ExpirationTimer::Dispatch(double t, bool is_expire) {
    if ( is_expire )
        return;

    storage_mgr->Expire();
    storage_mgr->StartExpirationTimer();
}

Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") {}

void Manager::InitPostScript() {
    detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend");
    StartExpirationTimer();
}

BackendResult Manager::OpenBackend(const Tag& type, RecordValPtr config, TypePtr key_type, TypePtr val_type) {
    Component* c = Lookup(type);
    if ( ! c ) {
        return nonstd::unexpected<std::string>(
            util::fmt("Request to open unknown backend (%d:%d)", type.Type(), type.Subtype()));
    }

    if ( ! c->Factory() ) {
        return nonstd::unexpected<std::string>(
            util::fmt("Factory invalid for backend %s", GetComponentName(type).c_str()));
    }

    Backend* b = c->Factory()();

    if ( ! b ) {
        return nonstd::unexpected<std::string>(
            util::fmt("Failed to instantiate backend %s", GetComponentName(type).c_str()));
    }

    if ( auto res = b->Open(std::move(config), std::move(key_type), std::move(val_type)); res.has_value() ) {
        delete b;
        return nonstd::unexpected<std::string>(
            util::fmt("Failed to open backend %s: %s", GetComponentName(type).c_str(), res.value().c_str()));
    }

    // TODO: post storage_connection_established event

    BackendPtr bp = IntrusivePtr<Backend>{AdoptRef{}, b};

    {
        std::unique_lock<std::mutex> lk(backends_mtx);
        backends.push_back(bp);
    }

    return bp;
}

void Manager::CloseBackend(BackendPtr backend) {
    {
        std::unique_lock<std::mutex> lk(backends_mtx);
        auto it = std::find(backends.begin(), backends.end(), backend);
        if ( it == backends.end() )
            return;

        backends.erase(it);
    }

    backend->Done();

    // TODO: post storage_connection_lost event
}

void Manager::Expire() {
    DBG_LOG(DBG_STORAGE, "Expire running, have %zu backends to check", backends.size());
    std::unique_lock<std::mutex> lk(backends_mtx);
    for ( const auto& b : backends )
        b->Expire();
}

void Manager::StartExpirationTimer() {
    zeek::detail::timer_mgr->Add(
        new detail::ExpirationTimer(run_state::network_time + zeek::BifConst::Storage::expire_interval));
}

} // namespace zeek::storage
