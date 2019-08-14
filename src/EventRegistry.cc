#include "EventRegistry.h"
#include "RE.h"
#include "Reporter.h"

void EventRegistry::Register(EventHandlerPtr handler)
	{
	handlers[string(handler->Name())] = handler.Ptr();
	}

EventHandler* EventRegistry::Lookup(const string& name)
	{
	auto it = handlers.find(name);
	if ( it != handlers.end() )
		return it->second;

	return nullptr;
	}

EventRegistry::string_list EventRegistry::Match(RE_Matcher* pattern)
	{
	string_list names;

	for ( const auto& entry : handlers )
		{
		EventHandler* v = entry.second;
		if ( v->LocalHandler() && pattern->MatchExactly(v->Name()) )
			names.push_back(entry.first);
		}

	return names;
	}

EventRegistry::string_list EventRegistry::UnusedHandlers()
	{
	string_list names;

	for ( const auto& entry : handlers )
		{
		EventHandler* v = entry.second;
		if ( v->LocalHandler() && ! v->Used() )
			names.push_back(entry.first);
		}

	return names;
	}

EventRegistry::string_list EventRegistry::UsedHandlers()
	{
	string_list names;

	for ( const auto& entry : handlers )
		{
		EventHandler* v = entry.second;
		if ( v->LocalHandler() && v->Used() )
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
		EventHandler* v = entry.second;
		fprintf(stderr, "Registered event %s (%s handler / %s)\n", v->Name(),
				v->LocalHandler()? "local" : "no",
				*v ? "active" : "not active"
				);
		}
	}

void EventRegistry::SetErrorHandler(const string& name)
	{
	EventHandler* eh = Lookup(name);

	if ( eh )
		{
		eh->SetErrorHandler();
		return;
		}

	reporter->InternalWarning("unknown event handler '%s' in SetErrorHandler()",
	                          name.c_str());
	}

