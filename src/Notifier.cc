// See the file "COPYING" in the main distribution directory for copyright.

#include "Notifier.h"
#include "DebugLogger.h"

#include <set>

notifier::Registry notifier::registry;

notifier::Receiver::Receiver()
	{
	DBG_LOG(zeek::DBG_NOTIFIERS, "creating receiver %p", this);
	}

notifier::Receiver::~Receiver()
	{
	DBG_LOG(zeek::DBG_NOTIFIERS, "deleting receiver %p", this);
	}

notifier::Registry::~Registry()
	{
	while ( registrations.begin() != registrations.end() )
		Unregister(registrations.begin()->first);
	}

void notifier::Registry::Register(Modifiable* m, notifier::Receiver* r)
	{
	DBG_LOG(zeek::DBG_NOTIFIERS, "registering object %p for receiver %p", m, r);

	registrations.insert({m, r});
	++m->num_receivers;
	}

void notifier::Registry::Unregister(Modifiable* m, notifier::Receiver* r)
	{
	DBG_LOG(zeek::DBG_NOTIFIERS, "unregistering object %p from receiver %p", m, r);

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
	DBG_LOG(zeek::DBG_NOTIFIERS, "unregistering object %p from all notifiers", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		--i->first->num_receivers;

	registrations.erase(x.first, x.second);
	}

void notifier::Registry::Modified(Modifiable* m)
	{
	DBG_LOG(zeek::DBG_NOTIFIERS, "object %p has been modified", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(m);
	}

void notifier::Registry::Terminate()
	{
	std::set<Receiver*> receivers;

	for ( auto& r : registrations )
		receivers.emplace(r.second);

	for ( auto& r : receivers )
		r->Terminate();
	}

notifier::Modifiable::~Modifiable()
	{
	if ( num_receivers )
		registry.Unregister(this);
	}
