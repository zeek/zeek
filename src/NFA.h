// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Obj.h"
#include "zeek/List.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(CCL, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(EquivClass, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);

#define NO_ACCEPT 0

#define NO_UPPER_BOUND -1

#define SYM_BOL 256
#define SYM_EOL 257
#define NUM_SYM 258

#define SYM_EPSILON 259
#define SYM_CCL 260

namespace zeek::detail {

class NFA_State;
using NFA_state_list = PList<NFA_State>;

class NFA_State : public Obj  {
public:
	NFA_State(int sym, EquivClass* ec);
	explicit NFA_State(CCL* ccl);
	~NFA_State() override;

	void AddXtion(NFA_State* next_state)	{ xtions.push_back(next_state); }
	NFA_state_list* Transitions()		{ return &xtions; }
	void AddXtionsTo(NFA_state_list* ns);

	void SetAccept(int accept_val)	{ accept = accept_val; }
	int Accept() const		{ return accept; }

	// Returns a deep copy of this NFA state and everything it points
	// to.  Upon return, each state's marker is set to point to its
	// copy.
	NFA_State* DeepCopy();

	void SetMark(NFA_State* m)	{ mark = m; }
	NFA_State* Mark() const		{ return mark; }
	void ClearMarks();

	void SetFirstTransIsBackRef()	{ first_trans_is_back_ref = true; }

	int TransSym() const	{ return sym; }
	CCL* TransCCL() const	{ return ccl; }
	int ID() const		{ return id; }

	NFA_state_list* EpsilonClosure();

	void Describe(ODesc* d) const override;
	void Dump(FILE* f);

	// Recursivly count all the reachable states.
	unsigned int TotalMemoryAllocation() const;

protected:
	int sym;	// if SYM_CCL, then use ccl
	CCL* ccl;	// if nil, then use sym
	int accept;

	// Whether the first transition points backwards.  Used
	// to avoid reference-counting loops.
	bool first_trans_is_back_ref;

	int id;	// number that uniquely identifies this state

	NFA_state_list xtions;
	NFA_state_list* epsclosure;
	NFA_State* mark;
};

class EpsilonState : public NFA_State {
public:
	EpsilonState()	: NFA_State(SYM_EPSILON, nullptr)	{ }
};

class NFA_Machine : public Obj {
public:
	explicit NFA_Machine(NFA_State* first, NFA_State* final = nullptr);
	~NFA_Machine() override;

	NFA_State* FirstState() const	{ return first_state; }

	void SetFinalState(NFA_State* final)	{ final_state = final; }
	NFA_State* FinalState() const		{ return final_state; }

	void AddAccept(int accept_val);

	void MakeClosure()	{ MakePositiveClosure(); MakeOptional(); }
	void MakeOptional();
	void MakePositiveClosure();

	// re{lower,upper}; upper can be NO_UPPER_BOUND = infinity.
	void MakeRepl(int lower, int upper);

	void MarkBOL()		{ bol = 1; }
	void MarkEOL()		{ eol = 1; }

	NFA_Machine* DuplicateMachine();
	void LinkCopies(int n);
	void InsertEpsilon();
	void AppendEpsilon();

	void AppendState(NFA_State* new_state);
	void AppendMachine(NFA_Machine* new_mach);

	void Describe(ODesc* d) const override;
	void Dump(FILE* f);

	unsigned int MemoryAllocation() const
		{ return padded_sizeof(*this) + first_state->TotalMemoryAllocation(); }

protected:
	NFA_State* first_state;
	NFA_State* final_state;
	int bol, eol;
};

extern NFA_Machine* make_alternate(NFA_Machine* m1, NFA_Machine* m2);

// The epsilon closure is the set of all states reachable by an arbitrary
// number of epsilon transitions, which themselves do not have epsilon
// transitions going out, unioned with the set of states which have non-null
// accepting numbers.  "states" is deleted by the call.  The return value
// is the epsilon closure (sorted by state IDs()).
extern NFA_state_list* epsilon_closure(NFA_state_list* states);

// For sorting NFA states based on their ID fields (decreasing)
extern bool NFA_state_cmp_neg(const NFA_State* v1, const NFA_State* v2);

} // namespace zeek::detail
