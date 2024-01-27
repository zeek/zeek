// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/storage/Component.h"
#include "zeek/storage/backends/sqlite/SQLite.h"

namespace zeek::storage::backend::sqlite {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        AddComponent(new storage::Component("SQLITE", backends::sqlite::SQLite::Instantiate));

        plugin::Configuration config;
        config.name = "Zeek::SQLiteStorage";
        config.description = "SQLite backend for storage framework";
        return config;
    }
} plugin;

} // namespace zeek::storage::backend::sqlite
