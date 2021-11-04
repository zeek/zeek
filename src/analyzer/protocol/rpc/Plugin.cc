// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/rpc/MOUNT.h"
#include "zeek/analyzer/protocol/rpc/NFS.h"
#include "zeek/analyzer/protocol/rpc/Portmap.h"
#include "zeek/analyzer/protocol/rpc/RPC.h"

namespace zeek::plugin::detail::Zeek_RPC
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("NFS", zeek::analyzer::rpc::NFS_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component(
			"MOUNT", zeek::analyzer::rpc::MOUNT_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component(
			"Portmapper", zeek::analyzer::rpc::Portmapper_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Contents_RPC", nullptr));
		AddComponent(new zeek::analyzer::Component("Contents_NFS", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::RPC";
		config.description = "Analyzers for RPC-based protocols";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_RPC
