// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "X509.h"
#include "OCSP.h"

namespace plugin {
namespace Bro_X509 {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("X509", ::file_analysis::X509::Instantiate));
		AddComponent(new ::file_analysis::Component("OCSP", ::file_analysis::OCSP::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::X509";
		config.description = "X509 and OCSP analyzer";
		return config;
		}
} plugin;

}
}
