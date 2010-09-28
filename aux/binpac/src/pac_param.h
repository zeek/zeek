#ifndef pac_param_h
#define pac_param_h

#include "pac_common.h"
#include "pac_field.h"

class Param : public Object
{
public:
	Param(ID* id, Type* type); 
	~Param();

	ID *id() const			{ return id_; }
	Type *type() const		{ return type_; }
	const string & decl_str() const;
	Field *param_field() const	{ return param_field_; }

private:
	ID* id_;
	Type* type_;
	string decl_str_;
	Field *param_field_;
};

class ParamField : public Field
{
public:
	ParamField(const Param *param);

	void GenInitCode(Output *out, Env *env);
	void GenCleanUpCode(Output* out, Env* env);
};

// Returns the string with a list of param declarations separated by ','.
string ParamDecls(ParamList *params);

#if 0
// Generate assignments to parameters, in the form of "%s_ = %s;" % (id, id).
void GenParamAssignments(ParamList *params, Output *out_cc, Env *env);

// Generate public access methods to parameter members.
void GenParamPubDecls(ParamList *params, Output *out_h, Env *env);

// Generate private definitions of parameter members.
void GenParamPrivDecls(ParamList *params, Output *out_h, Env *env);
#endif

#endif  // pac_param_h
