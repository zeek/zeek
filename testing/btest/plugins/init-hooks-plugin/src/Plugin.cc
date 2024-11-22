#include "Plugin.h"

#include <cstdio>
namespace btest::plugin::Demo_InitHooks {
Plugin plugin;
}

using namespace btest::plugin::Demo_InitHooks;

zeek::plugin::Configuration Plugin::Configure() {
    setlinebuf(stdout);
    std::fprintf(stdout, "Configure()\n");
    zeek::plugin::Configuration config;
    config.name = "Demo::InitHooks";
    config.description = "Test Init and Done hooks";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}

void Plugin::InitPreScript() { std::fprintf(stdout, "InitPreScript()\n"); }

void Plugin::InitPostScript() { std::fprintf(stdout, "InitPostScript()\n"); }

void Plugin::InitPreExecution() { std::fprintf(stdout, "InitPreExecution()\n"); }

void Plugin::Done() { std::fprintf(stdout, "Done()\n"); }
