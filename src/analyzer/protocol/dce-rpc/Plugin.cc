// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "DCE_RPC.h"

namespace plugin {
namespace Bro_DCE_RPC {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("DCE_RPC", ::analyzer::dce_rpc::DCE_RPC_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Contents_DCE_RPC", 0));

		plugin::Configuration config;
		config.name = "Bro::DCE_RPC";
		config.description = "DCE-RPC analyzer";
		return config;
		}
} plugin;

}
}
