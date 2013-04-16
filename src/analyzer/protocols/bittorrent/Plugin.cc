
#include "plugin/Plugin.h"

#include "BitTorrent.h"
#include "BitTorrentTracker.h"

BRO_PLUGIN_BEGIN(BitTorrent)
	BRO_PLUGIN_DESCRIPTION("BitTorrent Analyzer");
	BRO_PLUGIN_ANALYZER("BitTorrent", BitTorrent_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_ANALYZER("BitTorrentTracker", BitTorrentTracker_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
