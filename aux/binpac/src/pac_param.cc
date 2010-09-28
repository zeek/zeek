#include "pac_decl.h"
#include "pac_exttype.h"
#include "pac_field.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_type.h"
#include "pac_utils.h"

#include "pac_param.h"

Param::Param(ID* id, Type *type)
	: id_(id), type_(type)
	{
	if ( ! type_ )
		type_ = extern_type_int->Clone();

	decl_str_ = strfmt("%s %s", 
	                   type_->DataTypeConstRefStr().c_str(), 
	                   id_->Name());

	param_field_ = new ParamField(this);
	}

Param::~Param()
	{
	}

const string &Param::decl_str() const
	{ 
	ASSERT(!decl_str_.empty()); 
	return decl_str_; 
	}

string ParamDecls(ParamList *params)
	{
	string param_decls;

	int first = 1;
	foreach (i, ParamList, params)
			{
			Param* p = *i;
			const char* decl_str = p->decl_str().c_str();
			if ( first )
				first = 0;
			else
				param_decls += ", ";
			param_decls += decl_str;
			}
	return param_decls;
	}

ParamField::ParamField(const Param *param)
	: Field(PARAM_FIELD, 
		TYPE_NOT_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE,
		param->id(), 
		param->type())
	{
	}

void ParamField::GenInitCode(Output *out_cc, Env *env)
	{
	out_cc->println("%s = %s;", 
		env->LValue(id()), id()->Name());
	env->SetEvaluated(id());
	}

void ParamField::GenCleanUpCode(Output* out_cc, Env* env)
	{
	// Do nothing
	}
