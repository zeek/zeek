// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

#include "zeek/Desc.h"

namespace zeek::storage {

Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") {}

void Manager::InitPostScript() { detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend"); }

zeek::expected<BackendPtr, std::string> Manager::OpenBackend(const Tag& type, RecordValPtr options, TypePtr key_type,
                                                             TypePtr val_type) {
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

    if ( auto res = bp->Open(std::move(options), std::move(key_type), std::move(val_type)); res.has_value() ) {
        return zeek::unexpected<std::string>(
            util::fmt("Failed to open backend %s: %s", GetComponentName(type).c_str(), res.value().c_str()));
    }

    // TODO: post Storage::backend_opened event

    backends.push_back(bp);

    return bp;
}

void Manager::CloseBackend(BackendPtr backend) {
    auto it = std::find(backends.begin(), backends.end(), backend);
    if ( it == backends.end() )
        return;

    backends.erase(it);
    backend->Close();

    // TODO: post Storage::backend_lost event
}

} // namespace zeek::storage
