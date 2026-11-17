// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"

namespace zeek::plugin::detail::Zeek_Brotli {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::analyzer::Component("Brotli", nullptr));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Brotli";
        config.description = "Brotli decompression support analyzer";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_Brotli
