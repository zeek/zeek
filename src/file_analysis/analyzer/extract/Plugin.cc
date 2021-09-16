// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/file_analysis/Component.h"
#include "zeek/file_analysis/analyzer/extract/Extract.h"

namespace zeek::plugin::detail::Zeek_FileExtract
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::file_analysis::Component(
			"EXTRACT", zeek::file_analysis::detail::Extract::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileExtract";
		config.description = "Extract file content";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_FileExtract
