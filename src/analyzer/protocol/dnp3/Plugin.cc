// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/dnp3/DNP3.h"

namespace zeek::plugin::detail::Zeek_DNP3
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"DNP3_TCP", zeek::analyzer::dnp3::DNP3_TCP_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component(
			"DNP3_UDP", zeek::analyzer::dnp3::DNP3_UDP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::DNP3";
		config.description = "DNP3 UDP/TCP analyzers";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_DNP3
