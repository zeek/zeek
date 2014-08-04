// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "BitTorrent.h"
#include "BitTorrentTracker.h"

namespace plugin {
namespace Bro_BitTorrent {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("BitTorrent", ::analyzer::bittorrent::BitTorrent_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("BitTorrentTracker", ::analyzer::bittorrent::BitTorrentTracker_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::BitTorrent";
		config.description = "BitTorrent Analyzer";
		return config;
		}
} plugin;

}
}
