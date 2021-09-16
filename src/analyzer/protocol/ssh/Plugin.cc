// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/ssh/SSH.h"

namespace zeek::plugin::detail::Zeek_SSH
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("SSH", zeek::analyzer::ssh::SSH_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SSH";
		config.description = "Secure Shell analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_SSH
