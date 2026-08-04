
#pragma once

#include "zeek/plugin/Plugin.h"

namespace btest::plugin::Demo_Foo {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPreScript() override;
    void InitPostScript() override;
    void Done() override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_Foo
