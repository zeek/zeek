// A class describing a state-modyfing access to a Value or an ID.

#ifndef STATEACESSS_H
#define STATEACESSS_H

#include <set>
#include <map>
#include <string>

#include "SerialObj.h"

class Val;
class ID;
class MutableVal;
class HashKey;
class ODesc;
class Serializer;
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

class StateAccess : public SerialObj {
public:
	StateAccess(Opcode opcode, const ID* target, const Val* op1,
			const Val* op2 = 0, const Val* op3 = 0);
	StateAccess(Opcode opcode, const MutableVal* target, const Val* op1,
			const Val* op2 = 0, const Val* op3 = 0);

	// For tables, the idx operand may be given as an index HashKey.
	// This is for efficiency. While we need to reconstruct the index
	// if we are actually going to serialize the access, we can at
	// least skip it if we don't.
	StateAccess(Opcode opcode, const ID* target, const HashKey* op1,
			const Val* op2 = 0, const Val* op3 = 0);
	StateAccess(Opcode opcode, const MutableVal* target, const HashKey* op1,
			const Val* op2 = 0, const Val* op3 = 0);

	StateAccess(const StateAccess& sa);

	virtual ~StateAccess();

	// Replays this access in the our environment.
	void Replay();

	// Returns target ID which may be an internal one for unbound vals.
	ID* Target() const;

	void Describe(ODesc* d) const;

	bool Serialize(SerialInfo* info) const;
	static StateAccess* Unserialize(UnserialInfo* info);

	// Main entry point when StateAcesses are performed.
	// For every state-changing operation, this has to be called.
	static void Log(StateAccess* access);

	// If we're going to make additional non-replaying accesses during a
	// Replay(), we have to call these.
	static void SuspendReplay()	{ --replaying; }
	static void ResumeReplay()	{ ++replaying; }

private:
	StateAccess()	{ target.id = 0; op1.val = op2 = op3 = 0; }
	void RefThem();

	bool CheckOld(const char* op, ID* id, Val* index, Val* should, Val* is);
	bool CheckOldSet(const char* op, ID* id, Val* index, bool should, bool is);
	bool MergeTables(TableVal* dst, Val* src);

	DECLARE_SERIAL(StateAccess);

	Opcode opcode;
	union {
		ID* id;
		MutableVal* val;
	} target;

	union {
		Val* val;
		const HashKey* key;
	} op1;

	Val* op2;
	Val* op3;

	enum Type { TYPE_ID, TYPE_VAL, TYPE_MVAL, TYPE_KEY };
	Type target_type;
	Type op1_type;
	bool delete_op1_key;

	static int replaying;
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

		// Called when a change is being performed. Note that when these
		// methods are called, it is undefined whether the change has
		// already been done or is just going to be performed soon.
		virtual void Access(ID* id, const StateAccess& sa) = 0;
		virtual void Access(Val* val, const StateAccess& sa) = 0;
		virtual const char* Name() const;	// for debugging
	};

	NotifierRegistry()	{ }
	~NotifierRegistry()	{ }

	// Inform the given notifier if ID/Val changes.
	void Register(ID* id, Notifier* notifier);
	void Register(Val* val, Notifier* notifier);

	// Cancel notification for this ID/Val.
	void Unregister(ID* id, Notifier* notifier);
	void Unregister(Val* val, Notifier* notifier);

private:
	friend class StateAccess;
	void AccessPerformed(const StateAccess& sa);

	typedef std::set<Notifier*> NotifierSet;
	typedef std::map<std::string, NotifierSet*> NotifierMap;
	NotifierMap ids;
};

extern NotifierRegistry notifiers;

#endif
