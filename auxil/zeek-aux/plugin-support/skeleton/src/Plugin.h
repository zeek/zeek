
#pragma once

#include <zeek/plugin/Plugin.h>

namespace plugin {
namespace @PLUGIN_NAMESPACE@_@PLUGIN_NAME@ {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}
