// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/finger/Finger.h"

namespace zeek::plugin::detail::Zeek_Finger
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"Finger", zeek::analyzer::finger::Finger_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Finger";
		config.description = "Finger analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Finger
