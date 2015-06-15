// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "OCSP.h"

namespace plugin {
namespace Bro_OCSP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("OCSP", ::file_analysis::OCSP::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::OCSP";
		config.description = "OCSP analyzer";
		return config;
		}
} plugin;

}
}
