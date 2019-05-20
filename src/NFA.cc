// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "NFA.h"
#include "EquivClass.h"

static int nfa_state_id = 0;

NFA_State::NFA_State(int arg_sym, EquivClass* ec)
	{
	sym = arg_sym;
	ccl = 0;
	accept = NO_ACCEPT;
	first_trans_is_back_ref = false;
	mark = 0;
	epsclosure = 0;
	id = ++nfa_state_id;

	// Fix up equivalence classes based on this transition.  Note that any
	// character which has its own transition gets its own equivalence
	// class.  Thus only characters which are only in character classes
	// have a chance at being in the same equivalence class.  E.g. "a|b"
	// puts 'a' and 'b' into two different equivalence classes.  "[ab]"
	// puts them in the same equivalence class (barring other differences
	// elsewhere in the input).

	if ( ec && sym != SYM_EPSILON /* no associated symbol */ )
		ec->UniqueChar(sym);
	}

NFA_State::NFA_State(CCL* arg_ccl)
	{
	sym = SYM_CCL;
	ccl = arg_ccl;
	accept = NO_ACCEPT;
	first_trans_is_back_ref = false;
	mark = 0;
	id = ++nfa_state_id;
	epsclosure = 0;
	}

NFA_State::~NFA_State()
	{
	for ( int i = 0; i < xtions.length(); ++i )
		if ( i > 0 || ! first_trans_is_back_ref )
			Unref(xtions[i]);

	delete epsclosure;
	}

void NFA_State::AddXtionsTo(NFA_state_list* ns)
	{
	for ( int i = 0; i < xtions.length(); ++i )
		ns->append(xtions[i]);
	}

NFA_State* NFA_State::DeepCopy()
	{
	if ( mark )
		{
		Ref(mark);
		return mark;
		}

	NFA_State* copy = ccl ? new NFA_State(ccl) : new NFA_State(sym, 0);
	SetMark(copy);

	for ( int i = 0; i < xtions.length(); ++i )
		copy->AddXtion(xtions[i]->DeepCopy());

	return copy;
	}

void NFA_State::ClearMarks()
	{
	if ( mark )
		{
		SetMark(0);
		for ( int i = 0; i < xtions.length(); ++i )
			xtions[i]->ClearMarks();
		}
	}

NFA_state_list* NFA_State::EpsilonClosure()
	{
	if ( epsclosure )
		return epsclosure;

	epsclosure = new NFA_state_list;

	NFA_state_list states;
	states.append(this);
	SetMark(this);

	int i;
	for ( i = 0; i < states.length(); ++i )
		{
		NFA_State* ns = states[i];
		if ( ns->TransSym() == SYM_EPSILON )
			{
			NFA_state_list* x = ns->Transitions();
			for ( int j = 0; j < x->length(); ++j )
				{
				NFA_State* nxt = (*x)[j];
				if ( ! nxt->Mark() )
					{
					states.append(nxt);
					nxt->SetMark(nxt);
					}
				}

			if ( ns->Accept() != NO_ACCEPT )
				epsclosure->append(ns);
			}

		else
			// Non-epsilon transition - keep it.
			epsclosure->append(ns);
		}

	// Clear out markers.
	for ( i = 0; i < states.length(); ++i )
		states[i]->SetMark(0);

	// Make it fit.
	epsclosure->resize(0);

	return epsclosure;
	}

void NFA_State::Describe(ODesc* d) const
	{
	d->Add("NFA state");
	}

void NFA_State::Dump(FILE* f)
	{
	if ( mark )
		return;

	fprintf(f, "NFA state %d, sym = %d, accept = %d:\n", id, sym, accept);

	for ( int i = 0; i < xtions.length(); ++i )
		fprintf(f, "\ttransition to %d\n", xtions[i]->ID());

	SetMark(this);
	for ( int i = 0; i < xtions.length(); ++i )
		xtions[i]->Dump(f);
	}

unsigned int NFA_State::TotalMemoryAllocation() const
	{
	return padded_sizeof(*this)
		+ xtions.MemoryAllocation() - padded_sizeof(xtions)
		+ (epsclosure ? epsclosure->MemoryAllocation() : 0);
	}

NFA_Machine::NFA_Machine(NFA_State* first, NFA_State* final)
	{
	first_state = first;
	final_state = final ? final : first;
	eol = bol = 0;
	}

NFA_Machine::~NFA_Machine()
	{
	Unref(first_state);
	}

void NFA_Machine::InsertEpsilon()
	{
	NFA_State* eps = new EpsilonState();
	eps->AddXtion(first_state);
	first_state = eps;
	}

void NFA_Machine::AppendEpsilon()
	{
	AppendState(new EpsilonState());
	}

void NFA_Machine::AddAccept(int accept_val)
	{
	// Hang the accepting number off an epsilon state.  If it is associated
	// with a state that has a non-epsilon out-transition, then the state
	// will accept BEFORE it makes that transition, i.e., one character
	// too soon.

	if ( final_state->TransSym() != SYM_EPSILON )
		AppendState(new EpsilonState());

	final_state->SetAccept(accept_val);
	}

void NFA_Machine::LinkCopies(int n)
	{
	if ( n <= 0 )
		return;

	// Make all the copies before doing any appending, otherwise
	// subsequent DuplicateMachine()'s will include the extra
	// copies!
	NFA_Machine** copies = new NFA_Machine*[n];

	int i;
	for ( i = 0; i < n; ++i )
		copies[i] = DuplicateMachine();

	for ( i = 0; i < n; ++i )
		AppendMachine(copies[i]);

	delete [] copies;
	}

NFA_Machine* NFA_Machine::DuplicateMachine()
	{
	NFA_State* new_first_state = first_state->DeepCopy();
	NFA_Machine* new_m = new NFA_Machine(new_first_state, final_state->Mark());
	first_state->ClearMarks();

	return new_m;
	}

void NFA_Machine::AppendState(NFA_State* s)
	{
	final_state->AddXtion(s);
	final_state = s;
	}

void NFA_Machine::AppendMachine(NFA_Machine* m)
	{
	AppendEpsilon();
	final_state->AddXtion(m->FirstState());
	final_state = m->FinalState();

	Ref(m->FirstState());	// so states stay around after the following
	Unref(m);
	}

void NFA_Machine::MakeOptional()
	{
	InsertEpsilon();
	AppendEpsilon();
	first_state->AddXtion(final_state);
	Ref(final_state);
	}

void NFA_Machine::MakePositiveClosure()
	{
	AppendEpsilon();
	final_state->AddXtion(first_state);

	// Don't Ref the state the final epsilon points to, otherwise we'll
	// have reference cycles that lead to leaks.
	final_state->SetFirstTransIsBackRef();
	}

void NFA_Machine::MakeRepl(int lower, int upper)
	{
	NFA_Machine* dup = 0;
	if ( upper > lower || upper == NO_UPPER_BOUND )
		dup = DuplicateMachine();

	LinkCopies(lower - 1);

	if ( upper == NO_UPPER_BOUND )
		{
		dup->MakeClosure();
		AppendMachine(dup);
		return;
		}

	while ( upper > lower )
		{
		NFA_Machine* dup2;
		if ( --upper == lower )
			// Don't need "dup" for any further copies
			dup2 = dup;
		else
			dup2 = dup->DuplicateMachine();

		dup2->MakeOptional();
		AppendMachine(dup2);
		}
	}

void NFA_Machine::Describe(ODesc* d) const
	{
	d->Add("NFA machine");
	}

void NFA_Machine::Dump(FILE* f)
	{
	first_state->Dump(f);
	first_state->ClearMarks();
	}

NFA_Machine* make_alternate(NFA_Machine* m1, NFA_Machine* m2)
	{
	if ( ! m1 )
		return m2;
	if ( ! m2 )
		return m1;

	NFA_State* first = new EpsilonState();
	NFA_State* last = new EpsilonState();

	first->AddXtion(m1->FirstState());
	first->AddXtion(m2->FirstState());

	m1->AppendState(last);
	m2->AppendState(last);
	Ref(last);

	// Keep these around.
	Ref(m1->FirstState());
	Ref(m2->FirstState());

	Unref(m1);
	Unref(m2);

	return new NFA_Machine(first, last);
	}


NFA_state_list* epsilon_closure(NFA_state_list* states)
	{
	// We just keep one of this as it may get quite large.
	static IntSet closuremap;
	closuremap.Clear();

	NFA_state_list* closure = new NFA_state_list;

	for ( int i = 0; i < states->length(); ++i )
		{
		NFA_state_list* stateclosure = (*states)[i]->EpsilonClosure();

		for ( int j = 0; j < stateclosure->length(); ++j )
			{
			NFA_State* ns = (*stateclosure)[j];
			if ( ! closuremap.Contains(ns->ID()) )
				{
				closuremap.Insert(ns->ID());
				closure->sortedinsert(ns, NFA_state_cmp_neg);
				}
			}
		}

	// Make it fit.
	closure->resize(0);

	delete states;

	return closure;
	}

int NFA_state_cmp_neg(const void* v1, const void* v2)
	{
	const NFA_State* n1 = (const NFA_State*) v1;
	const NFA_State* n2 = (const NFA_State*) v2;

	if ( n1->ID() < n2->ID() )
		return -1;
	else if ( n1->ID() == n2->ID() )
		return 0;
	else
		return 1;
	}
