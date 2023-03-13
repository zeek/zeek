
#include "Plugin.h"

#include "Foo.h"
#include "analyzer/Component.h"
#include "analyzer/Manager.h"

namespace btest::plugin::Demo_Foo
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(
		new zeek::analyzer::Component("Foo", btest::plugin::Demo_Foo::Foo::Instantiate, 1));

	zeek::plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo test analyzer";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

void Plugin::InitPostScript()
	{
	auto tag = ::zeek::analyzer_mgr->GetAnalyzerTag("Foo");
	if ( ! tag )
		::zeek::reporter->FatalError("cannot get analyzer Tag");

	zeek::analyzer_mgr->RegisterAnalyzerForPort(tag, TransportProto::TRANSPORT_TCP, 4243);
	}
