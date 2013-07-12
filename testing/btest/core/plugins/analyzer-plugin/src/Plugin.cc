
#include <plugin/Plugin.h>

#include "Foo.h"

BRO_PLUGIN_BEGIN(Demo, Foo)
	BRO_PLUGIN_VERSION(1);
	BRO_PLUGIN_DESCRIPTION("A Foo test analyzer");
	BRO_PLUGIN_ANALYZER("Foo", Foo::Foo_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(functions);
BRO_PLUGIN_END
