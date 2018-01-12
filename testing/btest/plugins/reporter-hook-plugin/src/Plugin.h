
#ifndef BRO_PLUGIN_Reporter_Hook
#define BRO_PLUGIN_Reporter_Hook

#include <plugin/Plugin.h>

namespace plugin {
namespace Reporter_Hook {

class Plugin : public ::plugin::Plugin
{
protected:
	bool HookReporter(const std::string& prefix, const EventHandlerPtr event,
	                  const Connection* conn, const val_list* addl, bool location,
	                  const Location* location1, const Location* location2,
	                  bool time, const std::string& buffer) override;

	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
