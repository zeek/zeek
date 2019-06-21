// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "InterConn.h"

namespace plugin {
namespace Zeek_InterConn {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("InterConn", ::analyzer::interconn::InterConn_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::InterConn";
		config.description = "InterConn analyzer deprecated";
		return config;
		}
} plugin;

}
}
