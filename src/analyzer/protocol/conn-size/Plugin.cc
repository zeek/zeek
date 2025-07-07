// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/Val.h"
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

namespace zeek::plugin::detail::Zeek_ConnSize {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::analyzer::Component("ConnSize", zeek::analyzer::conn_size::ConnSize_Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::ConnSize";
        config.description = "Connection size analyzer";
        return config;
    }

    // Load generic_packet_thresholds at InitPostScript() time.
    void InitPostScript() override {
        auto t = id::find_const<TableVal>("ConnThreshold::generic_packet_thresholds");
        std::vector<uint64_t> thresholds;
        thresholds.reserve(t->Size());

        auto lv = t->ToPureListVal();
        for ( auto i = 0; i < lv->Length(); i++ )
            thresholds.emplace_back(lv->Idx(i)->AsCount());
        std::sort(thresholds.begin(), thresholds.end());

        zeek::analyzer::conn_size::ConnSize_Analyzer::SetGenericPacketThresholds(thresholds);
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_ConnSize
