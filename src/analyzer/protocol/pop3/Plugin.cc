// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "POP3.h"

namespace plugin {
namespace Zeek_POP3 {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("POP3", ::analyzer::pop3::POP3_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::POP3";
		config.description = "POP3 analyzer";
		return config;
		}
} plugin;

}
}
