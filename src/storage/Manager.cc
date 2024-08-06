// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

namespace zeek::storage {

Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") {}

void Manager::InitPostScript() { detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend"); }

/**
 * Opens a new storage backend.
 *
 * @param type The tag for the type of backend being opened.
 * @param configuration A record val representing the configuration for this
 * type of backend.
 * @return A pointer to a backend instance.
 */
BackendPtr Manager::OpenBackend(const Tag& type, RecordValPtr config) {
    Component* c = Lookup(type);
    if ( ! c ) {
        reporter->Warning("Request to open unknown backend (%d:%d)", type.Type(), type.Subtype());
        return nullptr;
    }

    if ( ! c->Factory() ) {
        reporter->Warning("Failed to open backend %s\n", GetComponentName(type).c_str());
        return nullptr;
    }

    Backend* b = c->Factory()();

    if ( ! b ) {
        reporter->InternalWarning("Failed to instantiate backend %s\n", GetComponentName(type).c_str());
        return nullptr;
    }

    if ( auto res = b->Open(std::move(config)); ! res.first ) {
        reporter->InternalWarning("Failed to open backend %s\n", GetComponentName(type).c_str());
        delete b;
        return nullptr;
    }

    return IntrusivePtr<Backend>{AdoptRef{}, b};
}

void Manager::CloseBackend(BackendPtr backend) { backend->Done(); }

} // namespace zeek::storage
