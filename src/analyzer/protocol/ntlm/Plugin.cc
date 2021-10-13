// See the file in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/protocol/ntlm/NTLM.h"

namespace zeek::plugin::detail::Zeek_NTLM
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"NTLM", zeek::analyzer::ntlm::NTLM_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::NTLM";
		config.description = "NTLM analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_NTLM
