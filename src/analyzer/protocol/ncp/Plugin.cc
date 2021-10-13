// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/ncp/NCP.h"

namespace zeek::plugin::detail::Zeek_NCP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("NCP", zeek::analyzer::ncp::NCP_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Contents_NCP", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::NCP";
		config.description = "NCP analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_NCP
