// See the file  in the main distribution directory for copyright.

#include "Hash.h"
#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

namespace zeek::plugin::detail::Zeek_FileHash {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::file_analysis::Component("MD5", zeek::file_analysis::detail::MD5::Instantiate));
		AddComponent(new zeek::file_analysis::Component("SHA1", zeek::file_analysis::detail::SHA1::Instantiate));
		AddComponent(new zeek::file_analysis::Component("SHA256", zeek::file_analysis::detail::SHA256::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileHash";
		config.description = "Hash file content";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_FileHash
