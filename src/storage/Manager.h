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
     * @param options A record val representing the configuration for this type of
     * backend.
     * @param key_type The script-side type of the keys stored in the backend. Used for
     * validation of types.
     * @param val_type The script-side type of the values stored in the backend. Used for
     * validation of types and conversion during retrieval.
     * @return An optional value potentially containing an error string if needed. Will be
     * unset if the operation succeeded.
     */
    zeek::expected<BackendPtr, std::string> OpenBackend(const Tag& type, RecordValPtr options, TypePtr key_type,
                                                        TypePtr val_type);

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
