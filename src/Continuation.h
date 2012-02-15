// Helper class to implement continuation-like mechanisms for
// suspending/resuming tasks for incremental operation.
//
// TODO: - Document how to use this.
//       - Find some nice macro-based interface?

#ifndef continuation_h
#define continuation_h

#include "List.h"

class Continuation {
public:
	Continuation()	{ current_level = 0; suspend_level = -1; }

	// Returns true if we're called for the first time.
	bool NewInstance() const
		{ return suspend_level < current_level; }

	// Returns true if a function called by us has suspended itself.
	bool ChildSuspended() const
		{ return suspend_level > current_level;  }

	// Returns true if we have suspended before and are now called again to
	// resume our operation.
	bool Resuming() const
		{ return suspend_level == current_level; }

	// To be called just before we suspend operation for the time being.
	void Suspend()
		{ suspend_level = current_level; }

	// To be called right after we resumed operation.
	void Resume()
		{ suspend_level = -1; }

	// If we call a function which may suspend itself, we need to
	// enclose the call with calls to SaveContext() and RestoreContext().
	void SaveContext()		{ ++current_level; }
	void RestoreContext()		{ --current_level; }

	// We can store some user state which can be retrieved later.
	void SaveState(void* user_ptr)
		{ states.replace(current_level, user_ptr); }

	void* RestoreState() const
		{ return states[current_level]; }

private:
	int current_level;
	int suspend_level;

	declare(PList, void);
	typedef PList(void) voidp_list;

	voidp_list states;
};

#endif
