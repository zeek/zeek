// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "StringExtract.h"

namespace plugin {
namespace Bro_FileStringExtract {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("STRINGEXTRACT", ::file_analysis::StringExtract::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::FileStringExtract";
		config.description = "Extract specific string content from files";
		return config;
		}
} plugin;

}
}
