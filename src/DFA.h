// $Id: DFA.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.


#ifndef dfa_h
#define dfa_h

#include <assert.h>

// It's possible to use a fixed size cache of computed states for each DFA.
// If the number of DFA states reaches the given limit, old states are expired
// on a least-recently-used basis. This may impact the performance significantly
// if expired states have to be recalculated regularly, but it limits the
// amount of memory taken by a DFA.
//
// Enable by configuring with --with-expire-dfa-states.

class DFA_State;

// The cache marks expired states as invalid.
#define DFA_INVALID_STATE_PTR ((DFA_State*) -1)

// Transitions to the uncomputed state indicate that we haven't yet
// computed the state to go to.
#define DFA_UNCOMPUTED_STATE -2
#define DFA_UNCOMPUTED_STATE_PTR ((DFA_State_Handle*) DFA_UNCOMPUTED_STATE)

#ifdef EXPIRE_DFA_STATES

class DFA_State_Handle {
public:
	// The reference counting keeps track of this *handle* (not the state).
	void Ref()	{ assert(state); ++refcount; }
	void Unref()
		{
		if ( --refcount == 0 )
			delete this;
		}

	inline void Invalidate();
	bool IsValid() const		{ return state != DFA_INVALID_STATE_PTR; }

	DFA_State* State() const	{ return state; }
	DFA_State* operator->() const	{ return state; }

protected:
	friend class DFA_State_Cache;

	DFA_State_Handle(DFA_State* arg_state)
		{ state = arg_state; refcount = 1; }

	inline ~DFA_State_Handle();

	DFA_State* state;
	int refcount;
};

#else
typedef DFA_State DFA_State_Handle;
#endif

#include "NFA.h"

extern int dfa_state_cache_size;

class DFA_Machine;
class DFA_State;
struct CacheEntry;

class DFA_State : public BroObj {
public:
	DFA_State(int state_num, const EquivClass* ec,
			NFA_state_list* nfa_states, AcceptingSet* accept);
	~DFA_State();

	int StateNum() const		{ return state_num; }
	int NFAStateNum() const		{ return nfa_states->length(); }
	void AddXtion(int sym, DFA_State_Handle* next_state);

	inline DFA_State_Handle* Xtion(int sym, DFA_Machine* machine);

	const AcceptingSet* Accept() const	{ return accept; }
	void SymPartition(const EquivClass* ec);

	// ec_sym is an equivalence class, not a character.
	NFA_state_list* SymFollowSet(int ec_sym, const EquivClass* ec);

	void SetMark(DFA_State* m)	{ mark = m; }
	DFA_State* Mark() const		{ return mark; }
	void ClearMarks();

	// Returns the equivalence classes of ec's corresponding to this state.
	const EquivClass* MetaECs() const	{ return meta_ec; }

	void Describe(ODesc* d) const;
	void Dump(FILE* f, DFA_Machine* m);
	void Stats(unsigned int* computed, unsigned int* uncomputed);
	unsigned int Size();

	// Locking a state will keep it from expiring from a cache.
	void Lock()	{ ++lock; }
	void Unlock()	{ --lock; }

#ifdef EXPIRE_DFA_STATES
	bool IsLocked()	{ return lock != 0; }
#else
	bool IsLocked()	{ return true; }
	DFA_State* operator->(){ return this; }
#endif

protected:
	friend class DFA_State_Cache;

	DFA_State_Handle* ComputeXtion(int sym, DFA_Machine* machine);
	void AppendIfNew(int sym, int_list* sym_list);

	int state_num;
	int num_sym;

	DFA_State_Handle** xtions;

	AcceptingSet* accept;
	NFA_state_list* nfa_states;
	EquivClass* meta_ec;	// which ec's make same transition
	DFA_State* mark;
	int lock;
	CacheEntry* centry;

	static unsigned int transition_counter;	// see Xtion()
};

struct CacheEntry {
	DFA_State_Handle* state;
	HashKey* hash;
	CacheEntry* next;
	CacheEntry* prev;
};

class DFA_State_Cache {
public:
	DFA_State_Cache(int maxsize);
	~DFA_State_Cache();

	// If the caller stores the handle, it has to call Ref() on it.
	DFA_State_Handle* Lookup(const NFA_state_list& nfa_states,
					HashKey** hash);

	// Takes ownership of both; hash is the one returned by Lookup().
	DFA_State_Handle* Insert(DFA_State* state, HashKey* hash);

	void MoveToFront(DFA_State* state)	{ MoveToFront(state->centry); }

	int NumEntries() const	{ return states.Length(); }

	struct Stats {
		unsigned int dfa_states;

		// Sum over all NFA states per DFA state.
		unsigned int nfa_states;
		unsigned int computed;
		unsigned int uncomputed;
		unsigned int mem;
		unsigned int hits;
		unsigned int misses;
	};

	void GetStats(Stats* s);

private:
	void Remove(CacheEntry* e);
	void MoveToFront(CacheEntry* e);

	int maxsize;

	int hits;	// Statistics
	int misses;

	declare(PDict,CacheEntry);

	// Hash indexed by NFA states (MD5s of them, actually).
	PDict(CacheEntry) states;

	// List in LRU order.
	CacheEntry* head;
	CacheEntry* tail;
};

declare(PList,DFA_State);
typedef PList(DFA_State) DFA_state_list;

class DFA_Machine : public BroObj {
public:
	DFA_Machine(NFA_Machine* n, EquivClass* ec);
	DFA_Machine(int** xtion_ptrs, int num_states, int num_ecs,
			int* acc_array);
	~DFA_Machine();

	DFA_State_Handle* StartState() const	{ return start_state; }

	int NumStates() const	{ return dfa_state_cache->NumEntries(); }

	DFA_State_Cache* Cache()	{ return dfa_state_cache; }

	int Rep(int sym);

	void Describe(ODesc* d) const;
	void Dump(FILE* f);
	void DumpStats(FILE* f);

	unsigned int MemoryAllocation() const;

protected:
	friend class DFA_State;	// for DFA_State::ComputeXtion
	friend class DFA_State_Cache;

	int state_count;

	// The state list has to be sorted according to IDs.
	int StateSetToDFA_State(NFA_state_list* state_set, DFA_State_Handle*& d,
				const EquivClass* ec);
	const EquivClass* EC() const	{ return ec; }

	EquivClass* ec;	// equivalence classes corresponding to NFAs
	DFA_State_Handle* start_state;
	DFA_State_Cache* dfa_state_cache;

	NFA_Machine* nfa;
};

#ifdef EXPIRE_DFA_STATES

inline DFA_State_Handle* DFA_State::Xtion(int sym, DFA_Machine* machine)
	{
	Lock();

	// This is just a clumsy form of sampling... Instead of moving
	// the state to the front of our LRU cache on each transition (which
	// would be quite often) we just do it on every nth transition
	// (counted across all DFA states). This is based on the observation
	// that a very few of all states are used most of time.
	// (currently n=10000; should it be configurable?)
	if ( transition_counter++ % 10000 == 0 )
		machine->Cache()->MoveToFront(this);

	DFA_State_Handle* h;

	if ( xtions[sym] == DFA_UNCOMPUTED_STATE_PTR ||
	     (xtions[sym] && ! xtions[sym]->IsValid()) )
		h = ComputeXtion(sym, machine);
	else
		h = xtions[sym];

	Unlock();

	return h;
	}

inline DFA_State_Handle::~DFA_State_Handle()
	{
	if ( state != DFA_INVALID_STATE_PTR )
		delete state;
	}

inline void DFA_State_Handle::Invalidate()
	{
	assert(state!=DFA_INVALID_STATE_PTR);
	delete state;
	state = DFA_INVALID_STATE_PTR;
	Unref();
	}

// Not nice but helps avoiding some overhead in the non-expiration case.
static inline void StateLock(DFA_State_Handle* s)	{ s->State()->Lock(); }
static inline void StateUnlock(DFA_State_Handle* s)	{ s->State()->Unlock(); }
static inline void StateRef(DFA_State_Handle* s)	{ s->Ref(); }
static inline void StateUnref(DFA_State_Handle* s)	{ s->Unref(); }
static inline void StateInvalidate(DFA_State_Handle* s)	{ s->Invalidate(); }

static inline bool StateIsValid(DFA_State_Handle* s)
	{
	return ! s || s->IsValid();
	}

#else

inline DFA_State_Handle* DFA_State::Xtion(int sym, DFA_Machine* machine)
	{
	if ( xtions[sym] == DFA_UNCOMPUTED_STATE_PTR )
		return ComputeXtion(sym, machine);
	else
		return xtions[sym];
	}

static inline void StateLock(DFA_State_Handle* s)	{ }
static inline void StateUnlock(DFA_State_Handle* s)	{ }
static inline void StateRef(DFA_State_Handle* s)	{ }
static inline void StateUnref(DFA_State_Handle* s)	{ }
static inline void StateInvalidate(DFA_State_Handle* s)	{ }
static inline bool StateIsValid(DFA_State_Handle* s)	{ return true; }

#endif

#endif
