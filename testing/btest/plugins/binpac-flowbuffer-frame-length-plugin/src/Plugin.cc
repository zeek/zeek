#include "plugin/Plugin.h"

#include "FOO.h"
#include "analyzer/Component.h"

namespace btest::plugin::Foo_FOO
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::analyzer::Component(
			"FOO", btest::analyzer::FOO::FOO_Analyzer::InstantiateAnalyzer));

		zeek::plugin::Configuration config;
		config.name = "FOO::Foo";
		config.description = "Foo Analyzer analyzer";
		config.version.major = 1;
		config.version.minor = 0;
		return config;
		}
	} plugin;

	}
