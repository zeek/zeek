// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

namespace zeek::plugin::detail::Zeek_ConnSize
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"ConnSize", zeek::analyzer::conn_size::ConnSize_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ConnSize";
		config.description = "Connection size analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_ConnSize
