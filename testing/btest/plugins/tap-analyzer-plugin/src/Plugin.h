
#pragma once

#include "zeek/plugin/Plugin.h"

namespace btest::plugin::Demo_Hooks {

class Plugin : public zeek::plugin::Plugin {
protected:
    void HookSetupAnalyzerTree(zeek::Connection* conn) override;

    // Overridden from zeek::plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_Hooks
