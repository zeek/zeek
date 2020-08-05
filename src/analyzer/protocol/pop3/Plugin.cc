// See the file  in the main distribution directory for copyright.

#include "POP3.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_POP3 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("POP3", ::analyzer::pop3::POP3_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::POP3";
		config.description = "POP3 analyzer";
		return config;
		}
} plugin;

}
}
