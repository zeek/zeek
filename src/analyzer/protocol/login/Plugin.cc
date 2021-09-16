// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/login/Login.h"
#include "zeek/analyzer/protocol/login/RSH.h"
#include "zeek/analyzer/protocol/login/Rlogin.h"
#include "zeek/analyzer/protocol/login/Telnet.h"

namespace zeek::plugin::detail::Zeek_Login
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"Telnet", zeek::analyzer::login::Telnet_Analyzer::Instantiate));
		AddComponent(
			new zeek::analyzer::Component("Rsh", zeek::analyzer::login::Rsh_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component(
			"Rlogin", zeek::analyzer::login::Rlogin_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("NVT", nullptr));
		AddComponent(new zeek::analyzer::Component("Login", nullptr));
		AddComponent(new zeek::analyzer::Component("Contents_Rsh", nullptr));
		AddComponent(new zeek::analyzer::Component("Contents_Rlogin", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Login";
		config.description = "Telnet/Rsh/Rlogin analyzers";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Login
