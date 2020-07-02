// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "DCE_RPC.h"

namespace plugin {
namespace Zeek_DCE_RPC {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("DCE_RPC", ::analyzer::dce_rpc::DCE_RPC_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::DCE_RPC";
		config.description = "DCE-RPC analyzer";
		return config;
		}
} plugin;

}
}
