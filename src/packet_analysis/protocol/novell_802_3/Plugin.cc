// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/novell_802_3/Novell_802_3.h"

namespace zeek::plugin::Zeek_Novell_802_3 {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::packet_analysis::Component("NOVELL_802_3", zeek::packet_analysis::Novell_802_3::
                                                                              Novell_802_3Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::NOVELL_802_3";
        config.description = "Novell 802.3 variantx packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_Novell_802_3
