
#include "Plugin.h"

#include "zeek/conn_key/Component.h"

#include "Foo.h"

namespace btest::plugin::Demo_Foo {
Plugin plugin;
}

using namespace btest::plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::conn_key::Component("Foo", btest::plugin::Demo_Foo::FooFactory::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Demo::Foo";
    config.description = "A Foo ConnKey factory";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}
