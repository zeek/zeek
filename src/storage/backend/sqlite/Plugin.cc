// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/storage/Component.h"
#include "zeek/storage/backend/sqlite/SQLite.h"

namespace zeek::storage::backend::sqlite {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        AddComponent(new storage::BackendComponent("SQLITE", backend::sqlite::SQLite::Instantiate));

        plugin::Configuration config;
        config.name = "Zeek::Storage_Backend_SQLite";
        config.description = "SQLite backend for storage framework";
        return config;
    }
} plugin;

} // namespace zeek::storage::backend::sqlite
