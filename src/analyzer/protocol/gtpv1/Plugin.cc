// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/gtpv1/GTPv1.h"

namespace zeek::plugin::detail::Zeek_GTPv1
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"GTPv1", zeek::analyzer::gtpv1::GTPv1_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::GTPv1";
		config.description = "GTPv1 analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_GTPv1
