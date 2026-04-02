// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::detail::Zeek_XDP_Shunter {

class Plugin : public zeek::plugin::Plugin {
protected:
    // Overridden from zeek::plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;
};

extern Plugin plugin;

} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
