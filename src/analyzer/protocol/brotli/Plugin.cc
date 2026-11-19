// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/zeek-config.h"

#include "zeek/analyzer/Component.h"

namespace zeek::plugin::detail::Zeek_Brotli {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        // TODO: Support analyzers like this one have no proper component
        // pattern yet. If more are added (zstd, ...), design one.
#ifdef USE_BROTLI
        AddComponent(new zeek::analyzer::Component("Brotli", nullptr));
#endif

        zeek::plugin::Configuration config;
        config.name = "Zeek::Brotli";
        config.description = "Brotli decompression support analyzer";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_Brotli
