// See the file "COPYING" in the main distribution directory for copyright.

#include <set>

#include "zeek/Notifier.h"
#include "zeek/DebugLogger.h"

zeek::notifier::detail::Registry zeek::notifier::detail::registry;

namespace zeek::notifier::detail {

Receiver::Receiver()
	{
	DBG_LOG(DBG_NOTIFIERS, "creating receiver %p", this);
	}

Receiver::~Receiver()
	{
	DBG_LOG(DBG_NOTIFIERS, "deleting receiver %p", this);
	}

Registry::~Registry()
	{
	while ( registrations.begin() != registrations.end() )
		Unregister(registrations.begin()->first);
	}

void Registry::Register(Modifiable* m, Receiver* r)
	{
	DBG_LOG(DBG_NOTIFIERS, "registering object %p for receiver %p", m, r);

	registrations.insert({m, r});
	++m->num_receivers;
	}

void Registry::Unregister(Modifiable* m, Receiver* r)
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

void Registry::Unregister(Modifiable* m)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering object %p from all notifiers", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		--i->first->num_receivers;

	registrations.erase(x.first, x.second);
	}

void Registry::Modified(Modifiable* m)
	{
	DBG_LOG(DBG_NOTIFIERS, "object %p has been modified", m);

	auto x = registrations.equal_range(m);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(m);
	}

void Registry::Terminate()
	{
	std::set<Receiver*> receivers;

	for ( auto& r : registrations )
		receivers.emplace(r.second);

	for ( auto& r : receivers )
		r->Terminate();
	}

Modifiable::~Modifiable()
	{
	if ( num_receivers )
		registry.Unregister(this);
	}

} // namespace zeek::notifier::detail
