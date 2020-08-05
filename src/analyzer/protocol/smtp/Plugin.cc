// See the file  in the main distribution directory for copyright.

#include "SMTP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_SMTP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("SMTP", ::analyzer::smtp::SMTP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SMTP";
		config.description = "SMTP analyzer";
		return config;
		}
} plugin;

}
}
