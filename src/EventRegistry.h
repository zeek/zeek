// $Id: EventRegistry.h 6829 2009-07-09 09:12:59Z vern $
//
// Each event raised/handled by Bro is registered in the EventRegistry.

#ifndef EVENT_REGISTRY
#define EVENT_REGISTRY

#include "Func.h"
#include "List.h"
#include "Dict.h"
#include "EventHandler.h"

// The registry keeps track of all events that we provide or handle.
class EventRegistry {
public:
	EventRegistry()		{ }
	~EventRegistry()	{ }

	void Register(EventHandlerPtr handler);

	// Return nil if unknown.
	EventHandler* Lookup(const char* name);

	// Returns a list of all local handlers that match the given pattern.
	// Passes ownership of list.
	typedef const char constchar;	// PList doesn't like "const char"
	declare(PList, constchar);
	typedef PList(constchar) string_list;
	string_list* Match(RE_Matcher* pattern);

	// Associates a group with the given event.
	void SetGroup(const char* name, const char* group);

	// Enable/disable all members of the group.
	void EnableGroup(const char* group, bool enable);

	string_list* UnusedHandlers();
	string_list* UsedHandlers();
	void PrintDebug();

private:
	declare(PDict, EventHandler);
	typedef PDict(EventHandler) handler_map;
	handler_map handlers;
};

extern EventRegistry* event_registry;

#endif
