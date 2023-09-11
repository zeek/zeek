// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/ComponentManager.h"
#include "zeek/storage/Backend.h"
#include "zeek/storage/Component.h"

namespace zeek::storage {

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
     * @param options A record val representing the configuration for this
     * type of backend.
     * @return A pair containing a pointer to a backend and a string for
     * returning error messages if needed.
     */
    zeek::expected<BackendPtr, std::string> OpenBackend(const Tag& type, RecordValPtr options);

    /**
     * Closes a storage backend.
     */
    void CloseBackend(BackendPtr backend);

    // TODO:
    // - Hooks for storage-backed tables?
    // - Handling aggregation from workers on a single manager?

private:
    std::vector<BackendPtr> backends;
};

} // namespace zeek::storage

namespace zeek {

extern storage::Manager* storage_mgr;

} // namespace zeek
