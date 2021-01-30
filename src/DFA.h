// See the file "COPYING" in the main distribution directory for copyright.


#pragma once

#include <assert.h>
#include <sys/types.h> // for u_char
#include <map>
#include <string>

#include "zeek/NFA.h"
#include "zeek/RE.h" // for typedef AcceptingSet
#include "zeek/Obj.h"

namespace zeek::detail {

class DFA_State;
class DFA_Machine;

// Transitions to the uncomputed state indicate that we haven't yet
// computed the state to go to.
#define DFA_UNCOMPUTED_STATE -2
#define DFA_UNCOMPUTED_STATE_PTR ((DFA_State*) DFA_UNCOMPUTED_STATE)

class DFA_State : public Obj {
public:
	DFA_State(int state_num, const EquivClass* ec,
			NFA_state_list* nfa_states, AcceptingSet* accept);
	~DFA_State() override;

	int StateNum() const		{ return state_num; }
	int NFAStateNum() const		{ return nfa_states->length(); }
	void AddXtion(int sym, DFA_State* next_state);

	inline DFA_State* Xtion(int sym, DFA_Machine* machine);

	const AcceptingSet* Accept() const	{ return accept; }
	void SymPartition(const EquivClass* ec);

	// ec_sym is an equivalence class, not a character.
	NFA_state_list* SymFollowSet(int ec_sym, const EquivClass* ec);

	void SetMark(DFA_State* m)	{ mark = m; }
	DFA_State* Mark() const		{ return mark; }
	void ClearMarks();

	// Returns the equivalence classes of ec's corresponding to this state.
	const EquivClass* MetaECs() const	{ return meta_ec; }

	void Describe(ODesc* d) const override;
	void Dump(FILE* f, DFA_Machine* m);
	void Stats(unsigned int* computed, unsigned int* uncomputed);
	unsigned int Size();

protected:
	friend class DFA_State_Cache;

	DFA_State* ComputeXtion(int sym, DFA_Machine* machine);
	void AppendIfNew(int sym, int_list* sym_list);

	int state_num;
	int num_sym;

	DFA_State** xtions;

	AcceptingSet* accept;
	NFA_state_list* nfa_states;
	EquivClass* meta_ec;	// which ec's make same transition
	DFA_State* mark;

	static unsigned int transition_counter;	// see Xtion()
};

using DigestStr = std::basic_string<u_char>;

class DFA_State_Cache {
public:
	DFA_State_Cache();
	~DFA_State_Cache();

	// If the caller stores the handle, it has to call Ref() on it.
	DFA_State* Lookup(const NFA_state_list& nfa_states, DigestStr* digest);

	// Takes ownership of state; digest is the one returned by Lookup().
	DFA_State* Insert(DFA_State* state, DigestStr digest);

	int NumEntries() const	{ return states.size(); }

	struct Stats {
		// Sum of all NFA states
		unsigned int nfa_states;
		unsigned int dfa_states;
		unsigned int computed;
		unsigned int uncomputed;
		unsigned int mem;
		unsigned int hits;
		unsigned int misses;
	};

	void GetStats(Stats* s);

private:
	int hits;	// Statistics
	int misses;

	// Hash indexed by NFA states (MD5s of them, actually).
	std::map<DigestStr, DFA_State*> states;
};

class DFA_Machine : public Obj {
public:
	DFA_Machine(NFA_Machine* n, EquivClass* ec);
	~DFA_Machine() override;

	DFA_State* StartState() const	{ return start_state; }

	int NumStates() const	{ return dfa_state_cache->NumEntries(); }

	DFA_State_Cache* Cache()	{ return dfa_state_cache; }

	int Rep(int sym);

	void Describe(ODesc* d) const override;
	void Dump(FILE* f);

	unsigned int MemoryAllocation() const;

protected:
	friend class DFA_State;	// for DFA_State::ComputeXtion
	friend class DFA_State_Cache;

	int state_count;

	// The state list has to be sorted according to IDs.
	bool StateSetToDFA_State(NFA_state_list* state_set, DFA_State*& d,
				const EquivClass* ec);
	const EquivClass* EC() const	{ return ec; }

	EquivClass* ec;	// equivalence classes corresponding to NFAs
	DFA_State* start_state;
	DFA_State_Cache* dfa_state_cache;

	NFA_Machine* nfa;
};

inline DFA_State* DFA_State::Xtion(int sym, DFA_Machine* machine)
	{
	if ( xtions[sym] == DFA_UNCOMPUTED_STATE_PTR )
		return ComputeXtion(sym, machine);
	else
		return xtions[sym];
	}

} // namespace zeek::detail
