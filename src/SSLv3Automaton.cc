// $Id: SSLv3Automaton.cc 80 2004-07-14 20:15:50Z jason $

// ---SSLv3_Automaton----------------------------------------------------------

#include "SSLv3Automaton.h"

SSLv3_Automaton::SSLv3_Automaton(int arg_num_states, int num_trans,
					int error_state)
	{
	num_states = arg_num_states;
	states = new SSLv3_State*[num_states];
	for ( int i = 0; i < num_states; ++i )
		states[i] = new SSLv3_State(num_trans, error_state);
	}

SSLv3_Automaton::~SSLv3_Automaton()
	{
	for ( int i = 0; i < num_states; ++i )
		delete states[i];
	delete [] states;
	}

void SSLv3_Automaton::Describe(ODesc* d) const
	{
	d->Add("sslAutomaton");
	}

void SSLv3_Automaton::setStartState(int state)
	{
	if ( state < num_states )
		startState = state;
	}

void SSLv3_Automaton::addTrans(int state1, int trans, int state2)
	{
	if ( state1 < num_states && state2 < num_states )
		states[state1]->addTrans(trans, state2);
	}

int SSLv3_Automaton::getNextState(int state, int trans)
	{
	if ( state < num_states )
		return states[state]->getNextState(trans);
	else
		return 0;
	}

int SSLv3_Automaton::getStartState()
	{
	if (startState >= 0)
		return startState;
	else
		return -1;
	}

// ---SSLv3_State--------------------------------------------------------------

SSLv3_State::SSLv3_State(int num_trans, int error_state)
	{
	this->num_trans = num_trans;
	transitions = new int[num_trans];
	for ( int i = 0; i < num_trans; ++i )
		transitions[i] = error_state;
	}

SSLv3_State::~SSLv3_State()
	{
	delete [] transitions;
	}

void SSLv3_State::addTrans(int trans, int state)
	{
	if ( trans < num_trans )
		transitions[trans] = state;
	}

int SSLv3_State::getNextState(int trans)
	{
	if ( trans < num_trans )
		return transitions[trans];
	else
		return 0;
	}
