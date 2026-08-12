# @TEST-DOC: Validate that plugins can include hilti runtime headers
# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo HiltiInclude
# @TEST-EXEC: cp Plugin.h Plugin.cc src/
#
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -b -e 'event zeek_init() { }'

# @TEST-START-FILE Plugin.h
#pragma once

#include "zeek/plugin/Plugin.h"

namespace btest::plugin::Demo_HiltiInclude {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_HiltiInclude
# @TEST-END-FILE

# @TEST-START-FILE Plugin.cc
#include "Plugin.h"

#include <iostream>

#include <hilti/rt/fmt.h>

namespace btest::plugin::Demo_HiltiInclude {
Plugin plugin;
}

using namespace btest::plugin::Demo_HiltiInclude;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Demo::HiltiInclude";
    config.description = "Test that hilti runtime headers are usable from plugins";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;

    std::cout << hilti::rt::fmt("hilti::rt::fmt works: %d", 42) << std::endl;

    return config;
}
# @TEST-END-FILE
