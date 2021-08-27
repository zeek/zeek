// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/teredo/Teredo.h"

namespace zeek::plugin::detail::Zeek_Teredo
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::packet_analysis::Component(
			"Teredo", zeek::packet_analysis::teredo::TeredoAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Teredo";
		config.description = "Teredo packet analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Teredo
