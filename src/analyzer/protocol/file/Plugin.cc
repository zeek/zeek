// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/file/File.h"

namespace zeek::plugin::detail::Zeek_File
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("FTP_Data", zeek::analyzer::file::FTP_Data::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::File";
		config.description = "Generic file analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_File
