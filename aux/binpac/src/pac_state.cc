#include "pac_id.h"
#include "pac_output.h"
#include "pac_type.h"

#include "pac_state.h"

void StateVar::GenDecl(Output *out_h, Env *env)
	{
	out_h->println("%s %s;", 
		type_->DataTypeStr().c_str(), 
		env->LValue(id_));
	}

void StateVar::GenAccessFunction(Output *out_h, Env *env)
	{
	out_h->println("%s %s const	{ return %s; }", 
		type_->DataTypeConstRefStr().c_str(), 
		env->RValue(id_), 
		env->LValue(id_));
	}

void StateVar::GenSetFunction(Output *out_h, Env *env)
	{
	out_h->println("void %s(%s x) 	{ %s = x; }", 
		set_function(id_).c_str(),
		type_->DataTypeConstRefStr().c_str(), 
		env->LValue(id_));
	}

void StateVar::GenInitCode(Output *out_cc, Env *env)
	{
	}

void StateVar::GenCleanUpCode(Output *out_cc, Env *env)
	{
	}
