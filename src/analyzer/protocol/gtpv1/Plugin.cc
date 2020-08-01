// See the file  in the main distribution directory for copyright.

#include "GTPv1.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_GTPv1 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("GTPv1", ::analyzer::gtpv1::GTPv1_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::GTPv1";
		config.description = "GTPv1 analyzer";
		return config;
		}
} plugin;

}
}
