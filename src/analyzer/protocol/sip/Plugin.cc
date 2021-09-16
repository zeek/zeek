// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/sip/SIP.h"
#include "zeek/analyzer/protocol/sip/SIP_TCP.h"

namespace zeek::plugin::detail::Zeek_SIP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("SIP", zeek::analyzer::sip::SIP_Analyzer::Instantiate));

		// We don't fully support SIP-over-TCP yet, so we don't activate this component.
		// AddComponent(new zeek::analyzer::Component("SIP_TCP",
		// ::analyzer::sip_tcp::SIP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SIP";
		config.description = "SIP analyzer UDP-only";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_SIP
