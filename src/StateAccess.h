// A class describing a state-modyfing access to a Value or an ID.
//
// TODO UPDATE: We provide a notifier framework to inform interested parties
// of modifications to selected global IDs/Vals. To get notified about a
// change, derive a class from Notifier and register the interesting
// instances with the NotifierRegistry.
//
// Note: For containers (e.g., tables), notifications are only issued if the
// container itself is modified, *not* for changes to the values contained
// therein.


#ifndef STATEACESSS_H
#define STATEACESSS_H

#include <set>
#include <unordered_map>
#include <string>

#include "util.h"
#include "DebugLogger.h"

namespace notifier  {

class Modifiable;

class Notifier {
public:
	Notifier()
		{
		DBG_LOG(DBG_NOTIFIERS, "creating notifier %p", this);
		}

	virtual ~Notifier()
		{
		DBG_LOG(DBG_NOTIFIERS, "destroying notifier %p", this);
		}

	// Called after a change has been performed.
	virtual void Modified(Modifiable* m) = 0;
};

// Singleton class.
class Registry {
public:
	Registry()	{ }
	~Registry();

	// Register a new notifier to be informed when an instance changes.
	void Register(Modifiable* m, Notifier* notifier);

	// Cancel a notifier's tracking an instace.
	void Unregister(Modifiable* m, Notifier* notifier);

	// Cancel all notifiers registered for an instance.
	void Unregister(Modifiable* m);

private:
	friend class Modifiable;

	// Inform all registered notifiers of a modification to an instance.
	void Modified(Modifiable* m);

	typedef std::unordered_multimap<Modifiable*, Notifier*> ModifiableMap;
	ModifiableMap registrations;
};


class Registry;
extern Registry registry;

// Base class for objects wanting to signal modifications to the registry.
class Modifiable {
protected:
	friend class Registry;

	Modifiable()	{}
	virtual ~Modifiable();

	void Modified()
		{
		if ( notifiers )
			registry.Modified(this);
		}

	// Number of currently registered notifiers for this instance.
	uint64 notifiers;
};

}


#endif
