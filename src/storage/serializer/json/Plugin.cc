// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/storage/Component.h"
#include "zeek/storage/serializer/json/JSON.h"

namespace zeek::storage::serializer::json {

class Plugin final : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        AddComponent(new storage::SerializerComponent("JSON", serializer::json::JSON::Instantiate));

        plugin::Configuration config;
        config.name = "Zeek::Storage_Serializer_JSON";
        config.description = "JSON serializer for storage framework";
        return config;
    }
} plugin;

} // namespace zeek::storage::serializer::json
