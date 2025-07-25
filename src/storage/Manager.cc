// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

#include <atomic>

#include "zeek/RunState.h"
#include "zeek/storage/ReturnCode.h"

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
        storage_mgr->expiration_thread = zeek::jthread([t]() { storage_mgr->Expire(t); });
    }

    storage_mgr->StartExpirationTimer();
}

Manager::Manager()
    : backend_mgr(plugin::ComponentManager<storage::BackendComponent>("Storage", "Backend")),
      serializer_mgr(plugin::ComponentManager<storage::SerializerComponent>("Storage", "Serializer")) {}

Manager::~Manager() {
    // TODO: should we shut down any existing backends? force-poll until all of their existing
    // operations finish and close them?

    // Don't leave all of these static objects to leak.
    ReturnCode::Cleanup();

    // NOTE: The expiration_thread object is a jthread and will be automatically joined
    // here as the object is destroyed.
}

void Manager::InitPostScript() {
    ReturnCode::Initialize();

    detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend");
    StartExpirationTimer();
}

zeek::expected<BackendPtr, std::string> Manager::InstantiateBackend(const Tag& type) {
    BackendComponent* c = backend_mgr.Lookup(type);
    if ( ! c )
        return zeek::unexpected<std::string>(
            util::fmt("Request to instantiate unknown backend type (%d:%d)", type.Type(), type.Subtype()));

    if ( ! c->Factory() )
        return zeek::unexpected<std::string>(
            util::fmt("Factory invalid for backend %s", backend_mgr.GetComponentName(type).c_str()));

    auto bp = c->Factory()();

    if ( ! bp )
        return zeek::unexpected<std::string>(
            util::fmt("Failed to instantiate backend %s", backend_mgr.GetComponentName(type).c_str()));

    return bp;
}

zeek::expected<std::unique_ptr<Serializer>, std::string> Manager::InstantiateSerializer(const Tag& type) {
    SerializerComponent* c = serializer_mgr.Lookup(type);
    if ( ! c )
        return zeek::unexpected<std::string>(
            util::fmt("Request to instantiate unknown serializer type (%d:%d)", type.Type(), type.Subtype()));

    if ( ! c->Factory() )
        return zeek::unexpected<std::string>(
            util::fmt("Factory invalid for serializer %s", serializer_mgr.GetComponentName(type).c_str()));

    auto bp = c->Factory()();

    if ( ! bp )
        return zeek::unexpected<std::string>(
            util::fmt("Failed to instantiate serializer %s", serializer_mgr.GetComponentName(type).c_str()));

    return bp;
}

OperationResult Manager::OpenBackend(BackendPtr backend, OpenResultCallback* cb, RecordValPtr options, TypePtr key_type,
                                     TypePtr val_type) {
    auto res = backend->Open(cb, std::move(options), std::move(key_type), std::move(val_type));
    if ( res.code != ReturnCode::SUCCESS && res.code != ReturnCode::IN_PROGRESS ) {
        res.err_str = util::fmt("Failed to open backend %s: %s", backend->Tag(), res.err_str.c_str());
        return res;
    }

    RegisterBackend(std::move(backend));

    // TODO: post Storage::backend_opened event

    return res;
}

OperationResult Manager::CloseBackend(BackendPtr backend, ResultCallback* cb) {
    // Expiration runs on a separate thread and loops over the vector of backends. The mutex
    // here ensures exclusive access. This one happens in a block because we can remove the
    // backend from the vector before actually closing it.
    {
        std::unique_lock<std::mutex> lk(backends_mtx);
        auto it = std::ranges::find(backends, backend);
        if ( it != backends.end() )
            backends.erase(it);
    }

    auto res = backend->Close(cb);

    // TODO: post Storage::backend_lost event

    return res;
}

void Manager::Expire(double t) {
    // Expiration runs on a separate thread and loops over the vector of backends. The mutex
    // here ensures exclusive access.
    std::unique_lock<std::mutex> lk(backends_mtx);

    for ( auto it = backends.begin(); it != backends.end() && ! run_state::terminating; ++it ) {
        if ( (*it)->IsOpen() )
            (*it)->Expire(t);
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
