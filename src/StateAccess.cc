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
	DBG_LOG(DBG_NOTIFIERS, "registering modifiable %p for notifier %p",
		m, notifier);

	registrations.insert({m, notifier});
	++m->notifiers;
	}

void notifier::Registry::Unregister(Modifiable* m, notifier::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering modifiable %p from notifier %p",
		m, notifier);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		{
		if ( i->second == notifier )
			{
			--i->first->notifiers;
			registrations.erase(i);
			break;
			}
		}
	}

void notifier::Registry::Unregister(Modifiable* m)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering modifiable %p from all notifiers",
		m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		--i->first->notifiers;

	registrations.erase(x.first, x.second);
	}

void notifier::Registry::Modified(Modifiable* m)
	{
	DBG_LOG(DBG_NOTIFIERS, "modification to modifiable %p", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(m);
	}

notifier::Modifiable::~Modifiable()
	{
	if ( notifiers )
		registry.Unregister(this);
	}
