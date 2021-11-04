// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/bittorrent/BitTorrent.h"
#include "zeek/analyzer/protocol/bittorrent/BitTorrentTracker.h"

namespace zeek::plugin::plugin::Zeek_BitTorrent
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"BitTorrent", zeek::analyzer::bittorrent::BitTorrent_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component(
			"BitTorrentTracker",
			zeek::analyzer::bittorrent::BitTorrentTracker_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::BitTorrent";
		config.description = "BitTorrent Analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::plugin::Zeek_BitTorrent
