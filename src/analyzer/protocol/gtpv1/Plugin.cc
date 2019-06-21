// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "GTPv1.h"

namespace plugin {
namespace Zeek_GTPv1 {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("GTPv1", ::analyzer::gtpv1::GTPv1_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::GTPv1";
		config.description = "GTPv1 analyzer";
		return config;
		}
} plugin;

}
}
