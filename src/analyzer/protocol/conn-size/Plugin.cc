// See the file  in the main distribution directory for copyright.

#include "ConnSize.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_ConnSize {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("ConnSize", ::analyzer::conn_size::ConnSize_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::ConnSize";
		config.description = "Connection size analyzer";
		return config;
		}
} plugin;

}
}
