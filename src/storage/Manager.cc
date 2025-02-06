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

BackendResult Manager::Instantiate(const Tag& type) {
    Component* c = Lookup(type);
    if ( ! c ) {
        return zeek::unexpected<std::string>(
            util::fmt("Request to open unknown backend (%d:%d)", type.Type(), type.Subtype()));
    }

    if ( ! c->Factory() ) {
        return zeek::unexpected<std::string>(
            util::fmt("Factory invalid for backend %s", GetComponentName(type).c_str()));
    }

    BackendPtr bp = c->Factory()();

    if ( ! bp ) {
        return zeek::unexpected<std::string>(
            util::fmt("Failed to instantiate backend %s", GetComponentName(type).c_str()));
    }

    return bp;
}

ErrorResult Manager::OpenBackend(BackendPtr backend, RecordValPtr config, TypePtr key_type, TypePtr val_type,
                                 OpenResultCallback* cb) {
    if ( auto res = backend->Open(std::move(config), std::move(key_type), std::move(val_type), cb); res.has_value() ) {
        return util::fmt("Failed to open backend %s: %s", backend->Tag(), res.value().c_str());
    }

    RegisterBackend(std::move(backend));

    // TODO: post storage_connection_established event

    return std::nullopt;
}

ErrorResult Manager::CloseBackend(BackendPtr backend, ErrorResultCallback* cb) {
    // Remove from the list always, even if the close may fail below and even in an async context.
    {
        std::unique_lock<std::mutex> lk(backends_mtx);
        auto it = std::find(backends.begin(), backends.end(), backend);
        if ( it != backends.end() )
            backends.erase(it);
    }

    if ( auto res = backend->Done(cb); res.has_value() ) {
        return util::fmt("Failed to close backend %s: %s", backend->Tag(), res.value().c_str());
    }

    return std::nullopt;

    // TODO: post storage_connection_lost event
}

void Manager::Expire() {
    DBG_LOG(DBG_STORAGE, "Expire running, have %zu backends to check", backends.size());
    std::unique_lock<std::mutex> lk(backends_mtx);
    for ( const auto& b : backends ) {
        if ( b->IsOpen() )
            b->Expire();
    }
}

void Manager::StartExpirationTimer() {
    zeek::detail::timer_mgr->Add(
        new detail::ExpirationTimer(run_state::network_time + zeek::BifConst::Storage::expire_interval));
}

void Manager::RegisterBackend(BackendPtr backend) {
    std::unique_lock<std::mutex> lk(backends_mtx);
    backends.push_back(std::move(backend));
}

} // namespace zeek::storage
