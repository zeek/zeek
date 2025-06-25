
#pragma once

#include "zeek/plugin/Plugin.h"

namespace btest::plugin::Demo_Foo {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_Foo
