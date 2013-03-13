
// Note: This is compiled from the top-level CMakeLists.txt and inherits its
// compiler settingss

#include "Reporter.h"

#include <string>

namespace bro {
namespace hilti {
namespace reporter {

std::list<Location *> locations;

void __push_location(const char* file, int line)
	{
	Location* loc = new Location(file, line, line, 0, 0);
	locations.push_back(loc);
	::reporter->PushLocation(loc);
	}

void __pop_location()
	{
	Location* loc = locations.back();
	delete loc;
	locations.pop_back();
	::reporter->PopLocation();
	}

char* __current_location()
	{
	assert(locations.size());
	Location* loc = locations.back();
	ODesc desc;
	loc->Describe(&desc);
	return strdup(desc.Description());
	}

extern void __error(const char* msg)
	{
	::reporter->Error("%s", msg);
	}

extern void __weird(Connection* conn, const char* msg)
	{
	::reporter->Weird(conn, msg);
	}

}
}
}


