#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_inputbuf.h"
#include "pac_output.h"
#include "pac_type.h"

InputBuffer::InputBuffer(Expr *expr)
	: DataDepElement(INPUT_BUFFER), expr_(expr)
	{
	}

bool InputBuffer::DoTraverse(DataDepVisitor *visitor)
	{
	if ( expr_ && ! expr_->Traverse(visitor) )
		return false;
	return true;
	}

bool InputBuffer::RequiresAnalyzerContext() const
	{
	return expr_->RequiresAnalyzerContext();
	}

DataPtr InputBuffer::GenDataBeginEnd(Output *out_cc, Env *env)
	{
	env->AddID(begin_of_data, TEMP_VAR, extern_type_const_byteptr);
	env->AddID(end_of_data, TEMP_VAR, extern_type_const_byteptr);

	out_cc->println("%s %s, %s;",
		extern_type_const_byteptr->DataTypeStr().c_str(),
		env->LValue(begin_of_data),
		env->LValue(end_of_data));

	out_cc->println("get_pointers(%s, &%s, &%s);",
		expr_->EvalExpr(out_cc, env),
		env->LValue(begin_of_data),
		env->LValue(end_of_data));

	env->SetEvaluated(begin_of_data);
	env->SetEvaluated(end_of_data);

	return DataPtr(env, begin_of_data, 0);
	}
