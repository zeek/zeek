// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/bench/BinpacBench.h"

namespace zeek::plugin::detail::Zeek_Bench {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::analyzer::Component("BINPAC_BENCH", zeek::analyzer::bench::BinpacBench_Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::BinpacBench";
        config.description = "BinpacBench analyzer";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_Bench
