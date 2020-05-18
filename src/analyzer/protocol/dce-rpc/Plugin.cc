// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "DCE_RPC.h"

namespace plugin {
namespace Zeek_DCE_RPC {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("DCE_RPC", ::analyzer::dce_rpc::DCE_RPC_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::DCE_RPC";
		config.description = "DCE-RPC analyzer";
		return config;
		}
} plugin;

}
}
