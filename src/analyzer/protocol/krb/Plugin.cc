// See the file in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/krb/KRB.h"
#include "zeek/analyzer/protocol/krb/KRB_TCP.h"

namespace zeek::plugin::detail::Zeek_KRB
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("KRB", zeek::analyzer::krb::KRB_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component(
			"KRB_TCP", zeek::analyzer::krb_tcp::KRB_Analyzer::Instantiate));
		zeek::plugin::Configuration config;
		config.name = "Zeek::KRB";
		config.description = "Kerberos analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_KRB
