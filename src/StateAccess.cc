#include "Val.h"
#include "StateAccess.h"
#include "Event.h"
#include "NetVar.h"
#include "DebugLogger.h"

notifier::Registry notifier::registry;

notifier::Registry::~Registry()
	{
	for ( auto i : registrations )
		Unregister(i.first);
	}

void notifier::Registry::Register(Modifiable* m, notifier::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "registering modifiable %p for notifier %s",
		m, notifier->Name());

	registrations.insert({m, notifier});
	++m->notifiers;
	}

void notifier::Registry::Unregister(Modifiable* m, notifier::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering modifiable %p from notifier %s",
		m, notifier->Name());

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		{
		if ( i->second == notifier )
			{
			registrations.erase(i);
			--i->first->notifiers;
			break;
			}
		}
	}

void notifier::Registry::Unregister(Modifiable* m)
	{
	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		Unregister(m, i->second);
	}

void notifier::Registry::Modified(Modifiable* m)
	{
	DBG_LOG(DBG_NOTIFIERS, "modification to modifiable %p", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(m);
	}

const char* notifier::Notifier::Name() const
	{
	return fmt("%p", this);
	}

