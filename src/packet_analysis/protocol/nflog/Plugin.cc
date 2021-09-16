// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/nflog/NFLog.h"

namespace zeek::plugin::Zeek_NFLog
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"NFLog", zeek::packet_analysis::NFLog::NFLogAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::NFLog";
		config.description = "NFLog packet analyzer";
		return config;
		}
	} plugin;

	}
