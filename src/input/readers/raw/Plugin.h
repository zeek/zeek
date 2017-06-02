// See the file in the main distribution directory for copyright.

#include <mutex>

#include "plugin/Plugin.h"

#include "Raw.h"

namespace plugin {
namespace Bro_RawReader {

class Plugin : public plugin::Plugin {
public:
	Plugin();

	plugin::Configuration Configure();

	virtual void InitPreScript();
	virtual void Done();

	std::unique_lock<std::mutex> ForkMutex();

private:
	std::mutex fork_mutex;

};

extern Plugin plugin;

}
}
