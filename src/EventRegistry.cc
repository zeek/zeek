#include "zeek/EventRegistry.h"

#include <algorithm>

#include "zeek/EventHandler.h"
#include "zeek/Func.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"

namespace zeek
	{

EventRegistry::EventRegistry() = default;
EventRegistry::~EventRegistry() noexcept = default;

EventHandlerPtr EventRegistry::Register(std::string_view name, bool is_from_script)
	{
	// If there already is an entry in the registry, we have a
	// local handler on the script layer.
	EventHandler* h = event_registry->Lookup(name);

	if ( h )
		{
		if ( ! is_from_script )
			not_only_from_script.insert(std::string(name));

		h->SetUsed();
		return h;
		}

	h = new EventHandler(std::string(name));
	event_registry->Register(h, is_from_script);

	h->SetUsed();

	return h;
	}

void EventRegistry::Register(EventHandlerPtr handler, bool is_from_script)
	{
	std::string name = handler->Name();

	handlers[name] = std::unique_ptr<EventHandler>(handler.Ptr());

	if ( ! is_from_script )
		not_only_from_script.insert(name);
	}

EventHandler* EventRegistry::Lookup(std::string_view name)
	{
	auto it = handlers.find(name);
	if ( it != handlers.end() )
		return it->second.get();

	return nullptr;
	}

bool EventRegistry::NotOnlyRegisteredFromScript(std::string_view name)
	{
	return not_only_from_script.count(std::string(name)) > 0;
	}

EventRegistry::string_list EventRegistry::Match(RE_Matcher* pattern)
	{
	string_list names;

	for ( const auto& entry : handlers )
		{
		EventHandler* v = entry.second.get();
		if ( v->GetFunc() && pattern->MatchExactly(v->Name()) )
			names.push_back(entry.first);
		}

	return names;
	}

EventRegistry::string_list EventRegistry::UnusedHandlers()
	{
	string_list names;

	for ( const auto& entry : handlers )
		{
		EventHandler* v = entry.second.get();
		if ( v->GetFunc() && ! v->Used() )
			names.push_back(entry.first);
		}

	return names;
	}

EventRegistry::string_list EventRegistry::UsedHandlers()
	{
	string_list names;

	for ( const auto& entry : handlers )
		{
		EventHandler* v = entry.second.get();
		if ( v->GetFunc() && v->Used() )
			names.push_back(entry.first);
		}

	return names;
	}

EventRegistry::string_list EventRegistry::AllHandlers()
	{
	string_list names;

	for ( const auto& entry : handlers )
		{
		names.push_back(entry.first);
		}

	return names;
	}

void EventRegistry::PrintDebug()
	{
	for ( const auto& entry : handlers )
		{
		EventHandler* v = entry.second.get();
		fprintf(stderr, "Registered event %s (%s handler / %s)\n", v->Name(),
		        v->GetFunc() ? "local" : "no", *v ? "active" : "not active");
		}
	}

void EventRegistry::SetErrorHandler(std::string_view name)
	{
	EventHandler* eh = Lookup(name);

	if ( eh )
		{
		eh->SetErrorHandler();
		return;
		}

	reporter->InternalWarning("unknown event handler '%s' in SetErrorHandler()",
	                          std::string(name).c_str());
	}

void EventRegistry::ActivateAllHandlers()
	{
	auto event_names = AllHandlers();
	for ( const auto& name : event_names )
		{
		if ( auto event = Lookup(name) )
			event->SetGenerateAlways();
		}
	}

EventGroupPtr EventRegistry::RegisterGroup(EventGroupKind kind, std::string_view name)
	{
	auto key = std::pair{kind, std::string{name}};
	if ( const auto& it = event_groups.find(key); it != event_groups.end() )
		return it->second;

	auto group = std::make_shared<EventGroup>(kind, name);
	return event_groups.emplace(key, group).first->second;
	}

EventGroupPtr EventRegistry::LookupGroup(EventGroupKind kind, std::string_view name)
	{
	auto key = std::pair{kind, std::string{name}};
	if ( const auto& it = event_groups.find(key); it != event_groups.end() )
		return it->second;

	return nullptr;
	}

EventGroup::EventGroup(EventGroupKind kind, std::string_view name) : kind(kind), name(name) { }

EventGroup::~EventGroup() noexcept { }

// Run through all ScriptFunc instances associated with this group and
// update their bodies after a group's enable/disable state has changed.
// Once that has completed, also update the Func's has_enabled_bodies
// setting based on the new state of its bodies.
//
// EventGroup is private friend with Func, so fiddling with the bodies
// and private members works and keeps the logic out of Func and away
// from the public zeek:: namespace.
void EventGroup::UpdateFuncBodies()
	{
	static auto is_group_disabled = [](const auto& g)
	{
		return g->IsDisabled();
	};

	for ( auto& func : funcs )
		{
		for ( auto& b : func->bodies )
			b.disabled = std::any_of(b.groups.cbegin(), b.groups.cend(), is_group_disabled);

		static auto is_body_enabled = [](const auto& b)
		{
			return ! b.disabled;
		};
		func->has_enabled_bodies = std::any_of(func->bodies.cbegin(), func->bodies.cend(),
		                                       is_body_enabled);
		}
	}

void EventGroup::Enable()
	{
	if ( enabled )
		return;

	enabled = true;

	UpdateFuncBodies();
	}

void EventGroup::Disable()
	{
	if ( ! enabled )
		return;

	enabled = false;

	UpdateFuncBodies();
	}

void EventGroup::AddFunc(detail::ScriptFuncPtr f)
	{
	funcs.insert(f);
	}

	} // namespace zeek
