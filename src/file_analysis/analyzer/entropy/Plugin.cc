// See the file  in the main distribution directory for copyright.

#include "Entropy.h"
#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

namespace zeek::plugin::detail::Zeek_FileEntropy {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::file_analysis::Component("ENTROPY", zeek::file_analysis::detail::Entropy::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileEntropy";
		config.description = "Entropy test file content";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_FileEntropy
