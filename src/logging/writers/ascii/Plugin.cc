// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/logging/writers/ascii/Ascii.h"

namespace zeek::plugin::detail::Zeek_AsciiWriter
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::logging::Component(
			"Ascii", zeek::logging::writer::detail::Ascii::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::AsciiWriter";
		config.description = "ASCII log writer";
		return config;
		}

protected:
	void InitPostScript() override { zeek::logging::writer::detail::Ascii::RotateLeftoverLogs(); }

	} plugin;

	} // namespace zeek::plugin::detail::Zeek_AsciiWriter
