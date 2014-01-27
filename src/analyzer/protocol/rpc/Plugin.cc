// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "RPC.h"
#include "NFS.h"
#include "Portmap.h"

namespace plugin {
namespace Bro_RPC {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("NFS", ::analyzer::rpc::NFS_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Portmapper", ::analyzer::rpc::Portmapper_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Contents_RPC", 0));
		AddComponent(new ::analyzer::Component("Contents_NFS", 0));

		plugin::Configuration config;
		config.name = "Bro::RPC";
		config.description = "Analyzers for RPC-based protocols";
		return config;
		}
} plugin;

}
}
