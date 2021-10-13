// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/protocol/dce-rpc/DCE_RPC.h"

namespace zeek::plugin::detail::Zeek_DCE_RPC
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"DCE_RPC", zeek::analyzer::dce_rpc::DCE_RPC_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::DCE_RPC";
		config.description = "DCE-RPC analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_DCE_RPC
