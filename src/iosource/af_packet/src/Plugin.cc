
#include "Plugin.h"
#include "AF_Packet.h"
#include "iosource/Component.h"

namespace plugin { namespace Zeek_AF_Packet { Plugin plugin; } }

using namespace plugin::Zeek_AF_Packet;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::iosource::PktSrcComponent("AF_PacketReader", "af_packet", ::iosource::PktSrcComponent::LIVE, ::iosource::pktsrc::AF_PacketSource::InstantiateAF_Packet));

	plugin::Configuration config;
	config.name = "Zeek::AF_Packet";
	config.description = "Packet acquisition via AF_Packet";
	config.version.major = 2;
	config.version.minor = 1;
	config.version.patch = 1;
	return config;
	}
