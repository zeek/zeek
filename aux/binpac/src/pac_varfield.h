#ifndef pac_varfield_h
#define pac_varfield_h

#include "pac_field.h"

// A private variable evaluated with parsing
class ParseVarField : public Field
{
public:
	ParseVarField(int is_class_member, ID* id, Type *type) 
	: Field(PARSE_VAR_FIELD, 
		TYPE_TO_BE_PARSED | is_class_member | NOT_PUBLIC_READABLE,
		id, type) {}
	void GenPubDecls(Output* out, Env* env) { /* do nothing */ }
};

// A public variable
class PubVarField : public Field
{
public:
	PubVarField(ID* id, Type *type) 
	: Field(PUB_VAR_FIELD, 
		TYPE_NOT_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE, 
		id, type) {}
	~PubVarField() {}
};

// A private variable
class PrivVarField : public Field
{
public:
	PrivVarField(ID* id, Type *type) 
	: Field(PRIV_VAR_FIELD, 
		TYPE_NOT_TO_BE_PARSED | CLASS_MEMBER | NOT_PUBLIC_READABLE, 
		id, type) {}
	~PrivVarField() {}

	void GenPubDecls(Output* out, Env* env) { /* do nothing */ }
};

class TempVarField : public Field
{
public:
	TempVarField(ID* id, Type *type) 
	: Field(TEMP_VAR_FIELD, 
		TYPE_NOT_TO_BE_PARSED | NOT_CLASS_MEMBER, 
		id, type) {}
	~TempVarField() {}
};

#endif  // pac_varfield_h
