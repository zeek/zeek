// See the file  in the main distribution directory for copyright.

#include "Extract.h"
#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

namespace plugin {
namespace Zeek_FileExtract {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new ::file_analysis::Component("EXTRACT", ::file_analysis::Extract::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileExtract";
		config.description = "Extract file content";
		return config;
		}
} plugin;

}
}
