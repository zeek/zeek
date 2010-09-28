#include "pac_dbg.h"
#include "pac_expr.h"
#include "pac_id.h"
#include "pac_primitive.h"
#include "pac_type.h"

string PPVal::ToCode(Env *env)
	{
	ASSERT(expr_);
	return string(expr_->EvalExpr(0, env));
	}

string PPSet::ToCode(Env *env)
	{
	ASSERT(expr_);
	return expr_->SetFunc(0, env);
	}

string PPType::ToCode(Env *env)
	{
	Type *type = expr_->DataType(env);
	if ( ! type )
		{
		}
	return type->DataTypeStr();
	}

string PPConstDef::ToCode(Env *env)
	{
	Type *type = expr_->DataType(env);
	env->AddID(id_, TEMP_VAR, type);
	env->SetEvaluated(id_);

	string type_str = type->DataTypeStr();
	return strfmt("%s %s = %s", 
	              type_str.c_str(),
	              env->LValue(id_),
	              expr_->EvalExpr(0, env));
	}
