// Each event raised/handled by Bro is registered in the EventRegistry.

#pragma once

#include "zeek-config.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

ZEEK_FORWARD_DECLARE_NAMESPACED(EventHandler, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(EventHandlerPtr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RE_Matcher, zeek);

namespace zeek {

// The registry keeps track of all events that we provide or handle.
class EventRegistry {
public:
	EventRegistry();
	~EventRegistry() noexcept;

	/**
	 * Performs a lookup for an existing event handler and returns it
	 * if one exists, or else creates one, registers it, and returns it.
	 * @param name  The name of the event handler to lookup/register.
	 * @return  The event handler.
	 */
	EventHandlerPtr Register(std::string_view name);

	void Register(EventHandlerPtr handler);

	// Return nil if unknown.
	EventHandler* Lookup(std::string_view name);

	// Returns a list of all local handlers that match the given pattern.
	// Passes ownership of list.
	using string_list = std::vector<std::string>;
	string_list Match(RE_Matcher* pattern);

	// Marks a handler as handling errors. Error handler will not be called
	// recursively to avoid infinite loops in case they trigger an error
	// themselves.
	void SetErrorHandler(std::string_view name);

	string_list UnusedHandlers();
	string_list UsedHandlers();
	string_list AllHandlers();

	void PrintDebug();

private:
	std::map<std::string, std::unique_ptr<EventHandler>, std::less<>> handlers;
};

extern EventRegistry* event_registry;

} // namespace zeek
