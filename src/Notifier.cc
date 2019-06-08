// See the file "COPYING" in the main distribution directory for copyright.

#include "DebugLogger.h"
#include "Notifier.h"

notifier::Registry notifier::registry;

notifier::Receiver::Receiver()
	{
	DBG_LOG(DBG_NOTIFIERS, "creating receiver %p", this);
	}

notifier::Receiver::~Receiver()
	{
	DBG_LOG(DBG_NOTIFIERS, "deleting receiver %p", this);
	}

notifier::Registry::~Registry()
	{
	for ( auto i : registrations )
		Unregister(i.first);
	}

void notifier::Registry::Register(Modifiable* m, notifier::Receiver* r)
	{
	DBG_LOG(DBG_NOTIFIERS, "registering object %p for receiver %p", m, r);

	registrations.insert({m, r});
	++m->num_receivers;
	}

void notifier::Registry::Unregister(Modifiable* m, notifier::Receiver* r)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering object %p from receiver %p", m, r);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		{
		if ( i->second == r )
			{
			--i->first->num_receivers;
			registrations.erase(i);
			break;
			}
		}
	}

void notifier::Registry::Unregister(Modifiable* m)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering object %p from all notifiers", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		--i->first->num_receivers;

	registrations.erase(x.first, x.second);
	}

void notifier::Registry::Modified(Modifiable* m)
	{
	DBG_LOG(DBG_NOTIFIERS, "object %p has been modified", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(m);
	}

notifier::Modifiable::~Modifiable()
	{
	if ( num_receivers )
		registry.Unregister(this);
	}
