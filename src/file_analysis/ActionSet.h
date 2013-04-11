#ifndef FILE_ANALYSIS_ACTIONSET_H
#define FILE_ANALYSIS_ACTIONSET_H

#include <queue>

#include "Action.h"
#include "Dict.h"
#include "CompHash.h"
#include "Val.h"

namespace file_analysis {

class File;
declare(PDict,Action);

/**
 * A set of file analysis actions indexed by ActionArgs.  Allows queueing
 * of addition/removals so that those modifications can happen at well-defined
 * times (e.g. to make sure a loop iterator isn't invalidated).
 */
class ActionSet {
public:

	ActionSet(File* arg_file);

	~ActionSet();

	/**
	 * @return true if action was instantiated/attached, else false.
	 */
	bool AddAction(RecordVal* args);

	/**
	 * @return true if action was able to be instantiated, else false.
	 */
	bool QueueAddAction(RecordVal* args);

	/**
	 * @return false if action didn't exist and so wasn't removed, else true.
	 */
	bool RemoveAction(const RecordVal* args);

	/**
	 * @return true if action exists at time of call, else false;
	 */
	bool QueueRemoveAction(const RecordVal* args);

	/**
	 * Perform all queued modifications to the currently active actions.
	 */
	void DrainModifications();

	IterCookie* InitForIteration() const
		{ return action_map.InitForIteration(); }

	Action* NextEntry(IterCookie* c)
		{ return action_map.NextEntry(c); }

protected:

	HashKey* GetKey(const RecordVal* args) const;
	Action* InstantiateAction(RecordVal* args) const;
	void InsertAction(Action* act, HashKey* key);
	bool RemoveAction(ActionTag tag, HashKey* key);

	File* file;
	CompositeHash* action_hash; /**< ActionArgs hashes Action map lookup. */
	PDict(Action) action_map;   /**< Actions indexed by ActionArgs. */

	class Modification {
	public:
		virtual ~Modification() {}
		virtual bool Perform(ActionSet* set) = 0;
		virtual void Abort() = 0;
	};

	class Add : public Modification {
	public:
		Add(Action* arg_act, HashKey* arg_key)
			: Modification(), act(arg_act), key(arg_key) {}
		virtual ~Add() {}
		virtual bool Perform(ActionSet* set);
		virtual void Abort() { delete act; delete key; }

	protected:
		Action* act;
		HashKey* key;
	};

	class Remove : public Modification {
	public:
		Remove(ActionTag arg_tag, HashKey* arg_key)
			: Modification(), tag(arg_tag), key(arg_key) {}
		virtual ~Remove() {}
		virtual bool Perform(ActionSet* set);
		virtual void Abort() { delete key; }

	protected:
		ActionTag tag;
		HashKey* key;
	};

	typedef queue<Modification*> ModQueue;
	ModQueue mod_queue;
};

} // namespace file_analysiss

#endif
