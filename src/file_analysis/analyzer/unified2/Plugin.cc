// See the file  in the main distribution directory for copyright.

// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Unified2.h"

namespace plugin {
namespace Bro_Unified2 {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("UNIFIED2", ::file_analysis::Unified2::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Unified2";
		config.description = "Analyze Unified2 alert files.";
		return config;
		}
} plugin;

}
}
