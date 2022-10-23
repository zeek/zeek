// Each event raised/handled by Zeek is registered in the EventRegistry.

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "zeek/IntrusivePtr.h"

namespace zeek
	{

// The different kinds of event groups that exist.
enum class EventGroupKind
	{
	Attribute,
	Module,
	};

class EventGroup;
class EventHandler;
class EventHandlerPtr;
class RE_Matcher;

using EventGroupPtr = std::shared_ptr<EventGroup>;

namespace detail
	{
class ScriptFunc;
using ScriptFuncPtr = zeek::IntrusivePtr<ScriptFunc>;
	}

// The registry keeps track of all events that we provide or handle.
class EventRegistry
	{
public:
	EventRegistry();
	~EventRegistry() noexcept;

	/**
	 * Performs a lookup for an existing event handler and returns it
	 * if one exists, or else creates one, registers it, and returns it.
	 * @param name  The name of the event handler to lookup/register.
	 * @param name  Whether the registration is coming from a script element.
	 * @return  The event handler.
	 */
	EventHandlerPtr Register(std::string_view name, bool is_from_script = false);

	void Register(EventHandlerPtr handler, bool is_from_script = false);

	// Return nil if unknown.
	EventHandler* Lookup(std::string_view name);

	// True if the given event handler (1) exists, and (2) was registered
	// in a non-script context (even if perhaps also registered in a script
	// context).
	bool NotOnlyRegisteredFromScript(std::string_view name);

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

	/**
	 * Marks all event handlers as active.
	 *
	 * By default, zeek does not generate (raise) events that have not handled by
	 * any scripts. This means that these events will be invisible to a lot of other
	 * event handlers - and will not raise :zeek:id:`new_event`. Calling this
	 * function will cause all event handlers to be raised. This is likely only
	 * useful for debugging and fuzzing, and likely causes reduced performance.
	 */
	void ActivateAllHandlers();

	/**
	 * Lookup or register a new event group.
	 *
	 * @return Pointer to the group.
	 */
	EventGroupPtr RegisterGroup(EventGroupKind kind, std::string_view name);

	/**
	 * Lookup an event group.
	 *
	 * @return Pointer to the group or nil if the group does not exist.
	 */
	EventGroupPtr LookupGroup(EventGroupKind kind, std::string_view name);

private:
	std::map<std::string, std::unique_ptr<EventHandler>, std::less<>> handlers;
	// Tracks whether a given event handler was registered in a
	// non-script context.
	std::unordered_set<std::string> not_only_from_script;

	// Map event groups identified by kind and name to their instances.
	std::map<std::pair<EventGroupKind, std::string>, std::shared_ptr<EventGroup>, std::less<>>
		event_groups;
	};

/**
 * Event group.
 *
 * Event and hook handlers (Func::Body instances) can be part of event groups.
 *
 * By default, all groups are enabled. An event or hook handler that is part of
 * any group that is disabled will be disabled and its execution prevented.
 *
 * Different kinds of event groups exist. Currently, attribute and module
 * event groups are implemented. The first relates to event handler tagged
 * with the &group attribute. The second is based on grouping event and hook
 * handlers by the module in which and these are implemented.
 *
 * Different kinds of are separate: Disabling the "HTTP" module event group does
 * not disable event handlers tagged with &group="HTTP", or vice versa.
 *
 * As an implementation detail: Event groups hold pointers to ScriptFunc
 * instances. Enabling or disabling individual groups iterates through all
 * bodies of the tracked ScriptFuncs and updates them to reflect the current
 * group state.
 */
class EventGroup
	{
public:
	EventGroup(EventGroupKind kind, std::string_view name);
	~EventGroup() noexcept;
	EventGroup(const EventGroup& g) = delete;
	EventGroup& operator=(const EventGroup&) = delete;

	/**
	 * Enable this event group and update all event handlers associated with it.
	 */
	void Enable();

	/**
	 * Disable this event group and update all event handlers associated with it.
	 */
	void Disable();

	/**
	 * @return True if this group is disabled else false.
	 */
	bool IsDisabled() { return ! enabled; }

	/**
	 * Add a function to this group that may contain matching bodies.
	 *
	 * @param f Pointer to the function to track.
	 */
	void AddFunc(detail::ScriptFuncPtr f);

private:
	void UpdateFuncBodies();

	EventGroupKind kind;
	std::string name;
	bool enabled = true;
	std::unordered_set<detail::ScriptFuncPtr> funcs;
	};

extern EventRegistry* event_registry;

	} // namespace zeek
