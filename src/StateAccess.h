// A class describing a state-modyfing access to a Value or an ID.

#ifndef STATEACESSS_H
#define STATEACESSS_H

#include <set>
#include <unordered_map>
#include <string>

class Val;
class ID;
class MutableVal;
class HashKey;
class ODesc;
class TableVal;

enum Opcode {	// Op1	Op2 Op3 (Vals)
	OP_NONE,
	OP_ASSIGN,	// new	old
	OP_ASSIGN_IDX,	// idx new  old
	OP_ADD,		// idx  old
	OP_INCR,	// idx  new old
	OP_INCR_IDX,	// idx  new old
	OP_DEL,		// idx  old
	OP_PRINT,	// args
	OP_EXPIRE,	// idx
	OP_READ_IDX,	// idx
};

// We provide a notifier framework to inform interested parties of
// modifications to selected global IDs/Vals. To get notified about a change,
// derive a class from Notifier and register the interesting IDs/Vals with
// the NotifierRegistry.
//
// Note: For containers (e.g., tables), notifications are only issued if the
// container itself is modified, *not* for changes to the values contained
// therein.

class NotifierRegistry {
public:
	class Notifier {
	public:
		virtual ~Notifier()	{ }

		// Called when a change is being performed. Note that when
		// these methods are called, it is undefined whether the
		// change has already been done or is just going to be
		// performed soon.
		virtual void Modified(ID* id) = 0;
		virtual void Modified(Val* val) = 0;
		virtual const char* Name() const;	// for debugging
	};

	NotifierRegistry()	{ }
	~NotifierRegistry();

	// Register a new notifier to be informed when ID/Val changes. Note
	// that the registry will store a reference to the target, keeping
	// the instance alive for as long as it's registered.
	void Register(ID* id, Notifier* notifier);
	void Register(Val* val, Notifier* notifier);

	// Cancel a notifier's tracking for this ID/Val, also releasing the
	// referencee being held.
	void Unregister(ID* id, Notifier* notifier);
	void Unregister(Val* val, Notifier* notifier);

	// Inform all registered notifiiers of a modification to a value/ID.
	void Modified(ID *id);
	void Modified(Val *val);

private:
	typedef std::unordered_multimap<Val*, Notifier*> ValMap;
	typedef std::unordered_multimap<ID*, Notifier*> IDMap;

	ValMap vals;
	IDMap ids;
};

extern NotifierRegistry notifiers;

#endif
