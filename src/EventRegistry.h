// Each event raised/handled by Bro is registered in the EventRegistry.

#ifndef EVENT_REGISTRY
#define EVENT_REGISTRY

#include <map>
#include <string>

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
	EventHandler* Lookup(const string& name);

	// Returns a list of all local handlers that match the given pattern.
	// Passes ownership of list.
	typedef vector<string> string_list;
	string_list Match(RE_Matcher* pattern);

	// Marks a handler as handling errors. Error handler will not be called
	// recursively to avoid infinite loops in case they trigger an error
	// themselves.
	void SetErrorHandler(const string& name);

	string_list UnusedHandlers();
	string_list UsedHandlers();
	string_list AllHandlers();

	void PrintDebug();

private:
	std::map<std::string, EventHandler*> handlers;
};

extern EventRegistry* event_registry;

#endif
