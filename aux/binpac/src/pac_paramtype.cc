#include "pac_context.h"
#include "pac_dataptr.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_output.h"
#include "pac_paramtype.h"
#include "pac_typedecl.h"

ParameterizedType::ParameterizedType(ID* type_id, ExprList* args)
	: Type(PARAMETERIZED), type_id_(type_id), args_(args)
	{
	checking_requires_analyzer_context_ = false;
	}

ParameterizedType::~ParameterizedType()
	{
	}

string ParameterizedType::EvalMember(const ID *member_id) const
	{
	Type *ty = ReferredDataType(true);
	return strfmt("->%s", ty->env()->RValue(member_id));
	}

string ParameterizedType::class_name() const
	{ 
	return type_id_->Name(); 
	}

Type *ParameterizedType::DoClone() const
	{
	return new ParameterizedType(type_id_->clone(), args_);
	}

void ParameterizedType::AddParamArg(Expr *arg)
	{
	args_->push_back(arg);
	}

bool ParameterizedType::DefineValueVar() const
	{
	return true;
	}

string ParameterizedType::DataTypeStr() const
	{
	return strfmt("%s *", type_id_->Name());
	}

Type *ParameterizedType::MemberDataType(const ID *member_id) const
	{
	Type *ref_type = TypeDecl::LookUpType(type_id_);
	if ( ! ref_type )
		return 0;
	return ref_type->MemberDataType(member_id);
	}

Type *ParameterizedType::ReferredDataType(bool throw_exception) const
	{
	Type* type = TypeDecl::LookUpType(type_id_);
	if ( ! type )
		{
		DEBUG_MSG("WARNING: cannot find referenced type for %s\n",
			type_id_->Name());
		if ( throw_exception )
			throw ExceptionIDNotFound(type_id_);
		}
	return type;
	}

int ParameterizedType::StaticSize(Env* env) const
	{
	return ReferredDataType(true)->StaticSize(env);
	}

void ParameterizedType::DoMarkIncrementalInput()
	{
	Type *ty = ReferredDataType(true);

	ty->MarkIncrementalInput();

	buffer_input_ = ty->buffer_input();
	incremental_parsing_ = ty->incremental_parsing();
	}

Type::BufferMode ParameterizedType::buffer_mode() const
	{
	// Note that the precedence is on attributes (&oneline or &length) 
	// specified on the parameterized type directly than on the type
	// declaration. 
	//
	// If both &oneline and &length are specified at the same place, 
	// use &length.
	//
	BufferMode mode = Type::buffer_mode();
	Type *ty = ReferredDataType(true);

	if ( mode != NOT_BUFFERABLE )
		return mode;
	else if ( ty->BufferableByLength() )
		return BUFFER_BY_LENGTH;
	else if ( ty->BufferableByLine() )
		return BUFFER_BY_LINE;

	return NOT_BUFFERABLE;
	}

bool ParameterizedType::ByteOrderSensitive() const
	{
	return ReferredDataType(true)->RequiresByteOrder();
	}

bool ParameterizedType::DoTraverse(DataDepVisitor *visitor)
	{
	if ( ! Type::DoTraverse(visitor) )
		return false;

	foreach(i, ExprList, args_)
		if ( ! (*i)->Traverse(visitor) )
			return false;

	Type *ty = ReferredDataType(false);
	if ( ty && ! ty->Traverse(visitor) )
		return false;

	return true;
	}

bool ParameterizedType::RequiresAnalyzerContext()
	{
	if ( checking_requires_analyzer_context_ )
		return false;
	checking_requires_analyzer_context_ = true;

	bool ret = false;
	// If any argument expression refers to analyzer context
	foreach(i, ExprList, args_)
		if ( (*i)->RequiresAnalyzerContext() )
			{
			ret = true;
			break;
			}
	ret = ret ||
	      Type::RequiresAnalyzerContext();

	if ( ! ret )
		{
		Type *ty = ReferredDataType(false);
		if ( ty )
	      		ret = ty->RequiresAnalyzerContext();
		}

	checking_requires_analyzer_context_ = false;
	return ret;
	}

void ParameterizedType::GenInitCode(Output* out_cc, Env* env)
	{
	ASSERT(persistent());
	out_cc->println("%s = 0;", env->LValue(value_var()));
	Type::GenInitCode(out_cc, env);
	}

void ParameterizedType::GenCleanUpCode(Output* out_cc, Env* env)
	{
	Type *ty = ReferredDataType(false);
	if ( ty && ty->attr_refcount() )
		out_cc->println("Unref(%s);", lvalue());
	else
		out_cc->println("delete %s;", lvalue());
	out_cc->println("%s = 0;", lvalue());
	Type::GenCleanUpCode(out_cc, env);
	}

string ParameterizedType::EvalParameters(Output* out_cc, Env *env) const
	{
	string arg_str;

	int first = 1;
	foreach (i, ExprList, args_)
		{
		Expr* e = *i;
		if ( first )
			first = 0;
		else
			arg_str += ", ";
		arg_str += e->EvalExpr(out_cc, env);
		}

	return arg_str;
	}

void ParameterizedType::GenNewInstance(Output *out_cc, Env *env)
	{
	out_cc->println("%s = new %s(%s);", 
		lvalue(), 
		type_id_->Name(), 
		EvalParameters(out_cc, env).c_str());
	}

void ParameterizedType::DoGenParseCode(Output* out_cc, Env* env,
		const DataPtr& data, int flags)
	{
	DEBUG_MSG("DoGenParseCode for %s\n", type_id_->Name());

	Type *ref_type = ReferredDataType(true);

	const char *parse_func;
	string parse_params;

	if ( buffer_mode() == BUFFER_NOTHING )
	        {
		ASSERT(!ref_type->incremental_input());
		parse_func = kParseFuncWithoutBuffer;
		parse_params = "0, 0";
		}
	else if ( ref_type->incremental_input() )
		{
		parse_func = kParseFuncWithBuffer;
		parse_params = env->RValue(flow_buffer_id);
		}
	else
		{
		parse_func = kParseFuncWithoutBuffer;
		parse_params = strfmt("%s, %s",
			data.ptr_expr(), 
			env->RValue(end_of_data));
		}

	if ( RequiresAnalyzerContext::compute(ref_type) )
		{
		parse_params += strfmt(", %s", env->RValue(analyzer_context_id));
		}

	if ( ref_type->RequiresByteOrder() )
		{
		env->Evaluate(out_cc, byteorder_id);
		parse_params += strfmt(", %s", env->RValue(byteorder_id));
		}

	string call_parse_func = strfmt("%s->%s(%s)",
			lvalue(), // parse() needs an LValue
			parse_func,
			parse_params.c_str());

	if ( incremental_input() )
		{
		if ( buffer_mode() == BUFFER_NOTHING )
		        {
		        out_cc->println("%s;", call_parse_func.c_str());
			out_cc->println("%s = true;", 
				env->LValue(parsing_complete_var()));
			}
		else
		        {
			ASSERT(parsing_complete_var());
			out_cc->println("%s = %s;",
				env->LValue(parsing_complete_var()),
				call_parse_func.c_str());

			// parsing_complete_var might have been already
			// evaluated when set to false
			if ( ! env->Evaluated(parsing_complete_var()) )
			        env->SetEvaluated(parsing_complete_var());
			}
		}
	else
		{
		if ( AddSizeVar(out_cc, env) )
			{
			out_cc->println("%s = %s;", 
				env->LValue(size_var()),
				call_parse_func.c_str());
			env->SetEvaluated(size_var());
			}
		else
			{
			out_cc->println("%s;", 
				call_parse_func.c_str());
			}
		}
	}

void ParameterizedType::GenDynamicSize(Output* out_cc, Env* env,
		const DataPtr& data)
	{
	GenParseCode(out_cc, env, data, 0);
	}

