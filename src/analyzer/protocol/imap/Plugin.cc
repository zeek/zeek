// See the file  in the main distribution directory for copyright.
#include "plugin/Plugin.h"
#include "IMAP.h"

namespace plugin {
namespace Zeek_IMAP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("IMAP", ::analyzer::imap::IMAP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::IMAP";
		config.description = "IMAP analyzer (StartTLS only)";
		return config;
		}
} plugin;

}
}
