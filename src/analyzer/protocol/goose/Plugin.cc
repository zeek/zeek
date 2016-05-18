
#include "plugin/Plugin.h"

#include "goose_pac.h"

namespace plugin { namespace Bro_GOOSE { 

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
	{
	plugin::Configuration config;
	config.name = "Bro::GOOSE";
	config.description = "A GOOSE analyzer";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}

} plugin;

} }
