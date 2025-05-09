#pragma once

#include <cstdio>

#include "zeek/plugin/Plugin.h"

namespace btest::plugin::Demo_InitHooks {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPreScript() override;
    void InitPostScript() override;
    void InitPreExecution() override;
    void Done() override;
};

extern Plugin plugin;
} // namespace btest::plugin::Demo_InitHooks
