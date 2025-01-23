// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/storage/Component.h"
#include "zeek/storage/backends/redis/Redis.h"

namespace zeek::storage::backend::redis {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        AddComponent(new storage::Component("REDIS", backends::redis::Redis::Instantiate));

        plugin::Configuration config;
        config.name = "Zeek::Storage_Backend_Redis";
        config.description = "Redis backend for storage framework";
        return config;
    }
} plugin;

} // namespace zeek::storage::backend::redis
