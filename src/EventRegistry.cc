// $Id: EventRegistry.cc 6829 2009-07-09 09:12:59Z vern $

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
		fprintf(stderr, "Registered event %s (%s handler)\n", v->Name(),
				v->LocalHandler()? "local" : "no");
		}
	}

void EventRegistry::SetGroup(const char* name, const char* group)
	{
	EventHandler* eh = Lookup(name);
	if ( ! eh )
		internal_error("unknown event handler in SetGroup()");

	eh->SetGroup(group);
	}

void EventRegistry::EnableGroup(const char* group, bool enable)
	{
	IterCookie* c = handlers.InitForIteration();

	HashKey* k;
	EventHandler* v;
	while ( (v = handlers.NextEntry(k, c)) )
		{
		delete k;

		if ( v->Group() && strcmp(v->Group(), group) == 0 )
			v->SetEnable(enable);
		}
	}

