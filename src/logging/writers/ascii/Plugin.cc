// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Ascii.h"

namespace plugin {
namespace Zeek_AsciiWriter {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new ::logging::Component("Ascii", ::logging::writer::Ascii::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::AsciiWriter";
		config.description = "ASCII log writer";
		return config;
		}
protected:
	void InitPostScript() override;

} plugin;

void Plugin::InitPostScript()
	{
	::logging::writer::Ascii::RotateLeftoverLogs();
	}
}
}
