// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/xmpp/XMPP.h"

namespace zeek::plugin::detail::Zeek_XMPP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"XMPP", zeek::analyzer::xmpp::XMPP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::XMPP";
		config.description = "XMPP analyzer (StartTLS only)";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_XMPP
