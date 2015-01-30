// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "InterConn.h"

namespace plugin {
namespace Bro_InterConn {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("InterConn", ::analyzer::interconn::InterConn_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::InterConn";
		config.description = "InterConn analyzer deprecated";
		return config;
		}
} plugin;

}
}
