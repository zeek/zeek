// See the file  in the main distribution directory for copyright.

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

	pthread_mutex_t * ForkMutex();

private:
	bool init;
	pthread_mutex_t fork_mutex;

};

extern Plugin plugin;

}
}
