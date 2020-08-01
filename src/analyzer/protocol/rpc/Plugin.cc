// See the file  in the main distribution directory for copyright.

#include "RPC.h"
#include "NFS.h"
#include "MOUNT.h"
#include "Portmap.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_RPC {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("NFS", ::analyzer::rpc::NFS_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("MOUNT", ::analyzer::rpc::MOUNT_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Portmapper", ::analyzer::rpc::Portmapper_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Contents_RPC", nullptr));
		AddComponent(new zeek::analyzer::Component("Contents_NFS", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::RPC";
		config.description = "Analyzers for RPC-based protocols";
		return config;
		}
} plugin;

}
}
