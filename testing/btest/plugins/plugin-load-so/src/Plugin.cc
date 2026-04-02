#include "Plugin.h"

#include <cstdio>

namespace plugin {
namespace Demo_Foo {
Plugin plugin;
}
} // namespace plugin

using namespace plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;

    std::printf("Configure()\n");

    return config;
}
void Plugin::InitPreScript() {
    std::printf("InitPreScript()\n");
    std::printf("InitPreScript() PluginPath: '%s'\n", PluginPath().c_str());
    std::printf("InitPreScript() PluginDirectory: '%s'\n", PluginDirectory().c_str());
}

void Plugin::InitPostScript() { std::printf("InitPostScript()\n"); }

void Plugin::Done() { std::printf("Done()\n"); }
