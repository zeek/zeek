
#ifndef BRO_PLUGIN_BRO_AF_PACKET
#define BRO_PLUGIN_BRO_AF_PACKET

#include <plugin/Plugin.h>

namespace plugin {
namespace Bro_AF_Packet {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
