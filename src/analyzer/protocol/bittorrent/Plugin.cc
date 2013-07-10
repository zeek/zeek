
#include "plugin/Plugin.h"

#include "BitTorrent.h"
#include "BitTorrentTracker.h"

BRO_PLUGIN_BEGIN(Bro, BitTorrent)
	BRO_PLUGIN_DESCRIPTION("BitTorrent Analyzer");
	BRO_PLUGIN_ANALYZER("BitTorrent", bittorrent::BitTorrent_Analyzer);
	BRO_PLUGIN_ANALYZER("BitTorrentTracker", bittorrent::BitTorrentTracker_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
