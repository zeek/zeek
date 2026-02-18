// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/storage/Component.h"
#include "zeek/storage/backend/postgresql/PostgreSQL.h"

namespace zeek::storage::backend::postgresql {

class Plugin final : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        AddComponent(new storage::BackendComponent("POSTGRESQL", backend::postgresql::PostgreSQL::Instantiate));

        plugin::Configuration config;
        config.name = "Zeek::Storage_Backend_PostgreSQL";
        config.description = "PostgreSQL backend for storage framework";
        return config;
    }
} plugin;

} // namespace zeek::storage::backend::postgresql
