// Each event raised/handled by Bro is registered in the EventRegistry.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

class EventHandler;
class EventHandlerPtr;
class RE_Matcher;

// The registry keeps track of all events that we provide or handle.
class EventRegistry {
public:
	EventRegistry();
	~EventRegistry() noexcept;

	void Register(EventHandlerPtr handler);

	// Return nil if unknown.
	EventHandler* Lookup(const std::string& name);

	// Returns a list of all local handlers that match the given pattern.
	// Passes ownership of list.
	using string_list = std::vector<std::string>;
	string_list Match(RE_Matcher* pattern);

	// Marks a handler as handling errors. Error handler will not be called
	// recursively to avoid infinite loops in case they trigger an error
	// themselves.
	void SetErrorHandler(const std::string& name);

	string_list UnusedHandlers();
	string_list UsedHandlers();
	string_list AllHandlers();

	void PrintDebug();

private:
	std::map<std::string, std::unique_ptr<EventHandler>> handlers;
};

extern EventRegistry* event_registry;
