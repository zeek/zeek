
#include "Plugin.h"
#include "AF_Packet.h"

namespace plugin { namespace Bro_AF_Packet { Plugin plugin; } }

using namespace plugin::Bro_AF_Packet;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::iosource::PktSrcComponent("AF_PacketReader", "af_packet", ::iosource::PktSrcComponent::LIVE, ::iosource::pktsrc::AF_PacketSource::InstantiateAF_Packet));

	plugin::Configuration config;
	config.name = "Bro::AF_Packet";
	config.description = "Packet acquisition via AF_Packet";
	config.version.major = 1;
	config.version.minor = 3;
	return config;
	}
