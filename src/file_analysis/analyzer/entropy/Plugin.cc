// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Entropy.h"

namespace plugin {
namespace Bro_FileEntropy {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("ENTROPY", ::file_analysis::Entropy::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::FileEntropy";
		config.description = "Entropy test file content";
		return config;
		}
} plugin;

}
}
