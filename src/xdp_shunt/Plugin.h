#pragma once

#include <zeek/plugin/Plugin.h>

namespace xdp::shunter {

class Plugin : public zeek::plugin::Plugin {
protected:
    // Overridden from zeek::plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;
};

extern Plugin plugin;

} // namespace xdp::shunter
