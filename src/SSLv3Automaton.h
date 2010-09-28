// $Id: SSLv3Automaton.h 80 2004-07-14 20:15:50Z jason $

#ifndef ssl_v3_automaton_h
#define ssl_v3_automaton_h

#include "Obj.h"
#include "SSLDefines.h"

class SSLv3_State;

/** Class SSLv3_Automaton is there for holding the transitions of a state machine.
 * The States are simply Integer Constants >= 0. Same for the transitions.
 * The SSLv3_Automaton holds a pointer to an array of pointers to the
 * states of the automaton. The array is indexed by the integer that
 * represents the corresponding state.
 * By default, the automaton is initialized with every transition leading to
 * the error_state.
 * By calling addTrans() (done in the SSLv3_Interpreter's BuildAutomaton()-method)
 * the proper transitions for the SSL automaton are created.
 * When calling getNextState(state, trans), you get the next state of the
 * automaton, according to state and trans.
 * */
class SSLv3_Automaton : public BroObj {
public:
	/* The constructor initialises the states 2-dim. array
	 * (which's size depends on num_states and num_trans).
	 * By default, every transition from every state leads to the error_state.
	 * @param num_states how many states the automaton has
	 * @param num_trans how many different transitions the automaton has
	 * @param error_state which Integer the error_state has
	 */
	SSLv3_Automaton(int num_states, int num_trans, int error_state);
	~SSLv3_Automaton();
	void Describe(ODesc* d) const;

	/* Sets the start state of the automaton.
	 * @param state the start state
	 */
	void setStartState(int state);

	/* This method is used for building up the automaton and defining
	 * from which state you get to which state which what transition.
	 * @param state1 the state from which the transition starts
	 * @param trans the transition itself
	 * @param to which state the transition leads
	 */
	void addTrans(int state1, int trans, int state2);

	/* Used for determinig into which state the automaton gets by using the
	 * given transition in the given state.
	 * @param state the state from which the transition starts
	 * @param trans the transition itself
	 * @return the state to which the transition leads
	 */
	int getNextState(int state, int trans);
	int getStartState();
	int OutRef()
		{
		return RefCnt();
		}

protected:
	int num_states;	///< how many states the automaton has
	SSLv3_State** states;	///< the pointer to the array of pointers that holds the states
	int startState;	///< the start state of the automaton

};

// ----------------------------------------------------------------------------

/** This class represents a state of the SSLv3_Automaton.
 * It holds a pointer to an array of integers, which corresponds to the
 * succeeding states of this state when "taking" a transition.
 * The transition array is indexed by the integer-values corresponding to
 * the transitions of the automaton.
 * */
class SSLv3_State {
public:
	/* The constructor initialises the state. By default, every transition
	 * of the automaton leads to the error_state.
	 * @param num_trans how many different transitions the automaton has
	 * @param error_state how many different transitions the automaton has
	 */
	SSLv3_State(int num_trans, int error_state);
	~SSLv3_State();

	/* This method is used for building up the automaton and is invoked by
	 * the SSLv3_Automaton's addTrans()-method. It defines the successing state
	 * of the automaton by taking the transition trans in this state.
	 * @param trans the transition,
	 * @param that leads to the state
	 */
	void addTrans(int trans, int state);

	/* Used for determinig into which state the automaton gets by using the
	 * given transition in the this state.
	 * @param trans which transition is to be taken
	 * @return the resulting state of the automaton
	 */
	int getNextState(int trans);

protected:
	int num_trans;	///< how many transitions the automaton has
	int* transitions;	///< the array of successing states of this state by taking the transition that indexes this array
};

#endif
