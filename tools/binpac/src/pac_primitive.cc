#include "pac_primitive.h"

#include "pac_dbg.h"
#include "pac_expr.h"
#include "pac_id.h"
#include "pac_type.h"

string PPVal::ToCode(Env* env)
	{
	ASSERT(expr_);
	return string(expr_->EvalExpr(nullptr, env));
	}

string PPSet::ToCode(Env* env)
	{
	ASSERT(expr_);
	return expr_->SetFunc(nullptr, env);
	}

string PPType::ToCode(Env* env)
	{
	Type* type = expr_->DataType(env);
	return type->DataTypeStr();
	}

string PPConstDef::ToCode(Env* env)
	{
	Type* type = expr_->DataType(env);
	env->AddID(id_, TEMP_VAR, type);
	env->SetEvaluated(id_);

	string type_str = type->DataTypeStr();
	return strfmt("%s %s = %s", type_str.c_str(), env->LValue(id_), expr_->EvalExpr(nullptr, env));
	}
