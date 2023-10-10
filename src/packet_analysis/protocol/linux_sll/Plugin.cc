// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/linux_sll/LinuxSLL.h"

namespace zeek::plugin::Zeek_LinuxSLL {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("LinuxSLL",
                                                 zeek::packet_analysis::LinuxSLL::LinuxSLLAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::LinuxSLL";
        config.description = "Linux cooked capture (SLL) packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_LinuxSLL
