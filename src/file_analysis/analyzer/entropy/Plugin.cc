// See the file  in the main distribution directory for copyright.

#include "Entropy.h"
#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

namespace plugin {
namespace Zeek_FileEntropy {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new ::file_analysis::Component("ENTROPY", ::file_analysis::Entropy::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileEntropy";
		config.description = "Entropy test file content";
		return config;
		}
} plugin;

}
}
