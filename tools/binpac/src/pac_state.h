#ifndef pac_state_h
#define pac_state_h

// Classes representing analyzer states.

#include "pac_common.h"

class StateVar
{
public:
	StateVar(ID *id, Type *type)
		: id_(id), type_(type) {}

	const ID *id() const	{ return id_; }
	Type *type() const	{ return type_; }

	void GenDecl(Output *out_h, Env *env);
	void GenAccessFunction(Output *out_h, Env *env);
	void GenSetFunction(Output *out_h, Env *env);
	void GenInitCode(Output *out_cc, Env *env);
	void GenCleanUpCode(Output *out_cc, Env *env);

private:
	ID *id_;
	Type *type_;
};

#endif  // pac_state_h
