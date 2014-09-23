// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "ConnSize.h"

namespace plugin {
namespace Bro_ConnSize {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("ConnSize", ::analyzer::conn_size::ConnSize_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::ConnSize";
		config.description = "Connection size analyzer";
		return config;
		}
} plugin;

}
}
