#include "EventRegistry.h"
#include "RE.h"
#include "RemoteSerializer.h"

void EventRegistry::Register(EventHandlerPtr handler)
	{
	HashKey key(handler->Name());
	handlers.Insert(&key, handler.Ptr());
	}

EventHandler* EventRegistry::Lookup(const char* name)
	{
	HashKey key(name);
	return handlers.Lookup(&key);
	}

EventRegistry::string_list* EventRegistry::Match(RE_Matcher* pattern)
	{
	string_list* names = new string_list;

	IterCookie* c = handlers.InitForIteration();

	HashKey* k;
	EventHandler* v;
	while ( (v = handlers.NextEntry(k, c)) )
		{
		if ( v->LocalHandler() && pattern->MatchExactly(v->Name()) )
			names->append(v->Name());

		delete k;
		}

	return names;
	}

EventRegistry::string_list* EventRegistry::UnusedHandlers()
	{
	string_list* names = new string_list;

	IterCookie* c = handlers.InitForIteration();

	HashKey* k;
	EventHandler* v;
	while ( (v = handlers.NextEntry(k, c)) )
		{
		if ( v->LocalHandler() && ! v->Used() )
			names->append(v->Name());

		delete k;
		}

	return names;
	}

EventRegistry::string_list* EventRegistry::UsedHandlers()
	{
	string_list* names = new string_list;

	IterCookie* c = handlers.InitForIteration();

	HashKey* k;
	EventHandler* v;
	while ( (v = handlers.NextEntry(k, c)) )
		{
		if ( v->LocalHandler() && v->Used() )
			names->append(v->Name());

		delete k;
		}

	return names;
	}

void EventRegistry::PrintDebug()
	{
	IterCookie* c = handlers.InitForIteration();

	HashKey* k;
	EventHandler* v;
	while ( (v = handlers.NextEntry(k, c)) )
		{
		delete k;
		fprintf(stderr, "Registered event %s (%s handler / %s)\n", v->Name(),
				v->LocalHandler()? "local" : "no",
				*v ? "active" : "not active"
				);
		}
	}

void EventRegistry::SetErrorHandler(const char* name)
	{
	EventHandler* eh = Lookup(name);

	if ( eh )
		{
		eh->SetErrorHandler();
		return;
		}

	reporter->InternalWarning(
	            "unknown event handler '%s' in SetErrorHandler()", name);
	}

