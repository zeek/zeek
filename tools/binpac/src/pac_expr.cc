#include "pac_case.h"
#include "pac_cstr.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_number.h"
#include "pac_output.h"
#include "pac_record.h"
#include "pac_regex.h"
#include "pac_strtype.h"
#include "pac_typedecl.h"
#include "pac_utils.h"

string OrigExprList(ExprList *list)
	{
	bool first = true;
	string str;
	foreach(i, ExprList, list)
		{
		Expr *expr = *i;
		if ( first )
			first = false;
		else
			str += ", ";
		str += expr->orig();
		}
	return str;
	}

string EvalExprList(ExprList *exprlist, Output *out, Env *env)
	{
	string val_list("");
	bool first = true;

	foreach(i, ExprList, exprlist)
		{
		if ( ! first )
			val_list += ", ";
		val_list += (*i)->EvalExpr(out, env);
		first = false;
		}

	return val_list;
	}

static const char* expr_fmt[] = 
{
#	define EXPR_DEF(type, num_op, fmt) fmt,
#	include "pac_expr.def"
#	undef EXPR_DEF
};

void Expr::init()
	{
	id_ = 0;
	num_ = 0;
	cstr_ = 0;
	regex_ = 0;
	num_operands_ = 0;
	operand_[0] = 0;
	operand_[1] = 0;
	operand_[2] = 0;
	args_ = 0;
	cases_ = 0;
	}

Expr::Expr(ID* arg_id)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = EXPR_ID;
	id_ = arg_id;
	num_operands_ = 0;
	orig_ = fmt("%s", id_->Name());
	}

Expr::Expr(Number* arg_num)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = EXPR_NUM;
	num_ = arg_num;
	num_operands_ = 0;
	orig_ = fmt("((int) %s)", num_->Str());
	}

Expr::Expr(ConstString *cstr)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = EXPR_CSTR;
	cstr_ = cstr;
	num_operands_ = 0;
	orig_ = cstr_->str();
	}

Expr::Expr(RegEx *regex)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = EXPR_REGEX;
	regex_ = regex;
	num_operands_ = 0;
	orig_ = fmt("/%s/", regex_->str().c_str());
	}

Expr::Expr(ExprType arg_type, Expr* op1)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = arg_type;
	num_operands_ = 1;
	operand_[0] = op1;
	orig_ = fmt(expr_fmt[expr_type_], op1->orig());
	}

Expr::Expr(ExprType arg_type, Expr* op1, Expr* op2)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = arg_type;
	num_operands_ = 2;
	operand_[0] = op1;
	operand_[1] = op2;
	operand_[2] = 0;
	orig_ = fmt(expr_fmt[expr_type_], op1->orig(), op2->orig());
	}

Expr::Expr(ExprType arg_type, Expr* op1, Expr* op2, Expr* op3)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = arg_type;
	num_operands_ = 3;
	operand_[0] = op1;
	operand_[1] = op2;
	operand_[2] = op3;
	orig_ = fmt(expr_fmt[expr_type_], op1->orig(), op2->orig(), op3->orig());
	}

Expr::Expr(ExprList *args)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = EXPR_CALLARGS;
	num_operands_ = -1;
	args_ = args;

	orig_ = OrigExprList(args_);
	}

Expr::Expr(Expr *index, CaseExprList *cases)
	: DataDepElement(EXPR)
	{
	init();
	expr_type_ = EXPR_CASE;
	num_operands_ = -1;
	operand_[0] = index;
	cases_ = cases;

	orig_ = strfmt("case %s of { ", index->orig());
	foreach(i, CaseExprList, cases_)
		{
		CaseExpr *c = *i;
		orig_ += strfmt("%s => %s; ", 
		                OrigExprList(c->index()).c_str(), 
		                c->value()->orig());
		}
	orig_ += "}";
	}

Expr::~Expr()
	{
	delete id_;
	delete operand_[0];
	delete operand_[1];
	delete operand_[2];
	delete_list(ExprList, args_);
	delete_list(CaseExprList, cases_);
	}

void Expr::AddCaseExpr(CaseExpr *case_expr)
	{
	ASSERT(str_.empty());
	ASSERT(expr_type_ == EXPR_CASE);
	ASSERT(cases_);
	cases_->push_back(case_expr);
	}

void Expr::GenStrFromFormat(Env *env)
	{
	// The format != "@custom@"
	ASSERT(*expr_fmt[expr_type_] != '@');

	switch ( num_operands_ )
		{
		case 1:
			str_ = fmt(expr_fmt[expr_type_], 
				operand_[0]->str());
			break; 
		case 2:
			str_ = fmt(expr_fmt[expr_type_], 
				operand_[0]->str(),
				operand_[1]->str());
			break; 
		case 3:
			str_ = fmt(expr_fmt[expr_type_], 
				operand_[0]->str(),
				operand_[1]->str(),
				operand_[2]->str());
			break; 
		default:
			DEBUG_MSG("num_operands_ = %d, orig = %s\n", num_operands_, orig());
			ASSERT(0);
			break;
		}
	}

namespace {

	RecordField *GetRecordField(const ID *id, Env *env)
		{
		Field* field = env->GetField(id);
		ASSERT(field);
		if ( field->tof() != RECORD_FIELD &&
		     field->tof() != PADDING_FIELD )
			throw Exception(id, "not a record field");
		RecordField *r = static_cast<RecordField *>(field);
		ASSERT(r);
		return r;
		}

}  // private namespace

void Expr::GenCaseEval(Output *out_cc, Env *env)
	{
	ASSERT(expr_type_ == EXPR_CASE);
	ASSERT(operand_[0]);
	ASSERT(cases_);

	Type *val_type = DataType(env);
	ID *val_var = env->AddTempID(val_type);

	// DataType(env) can return a null pointer if an enum value is not
	// defined.
	if ( ! val_type )
		throw Exception(this, "undefined case value");

	out_cc->println("%s %s;", 
	                val_type->DataTypeStr().c_str(), 
	                env->LValue(val_var));

	// force evaluation of IDs appearing in case stmt
        operand_[0]->ForceIDEval(out_cc, env);
	foreach(i, CaseExprList, cases_)
		(*i)->value()->ForceIDEval(out_cc, env);

	out_cc->println("switch ( %s )", operand_[0]->EvalExpr(out_cc, env));

	out_cc->inc_indent();
	out_cc->println("{");

	CaseExpr *default_case = 0;
	foreach(i, CaseExprList, cases_)
		{
		CaseExpr *c = *i;
		ExprList *index = c->index();
		if ( ! index )
			{
			if ( default_case )
				throw Exception(c, "duplicate default cases");
			default_case = c;
			}
		else
			{
			GenCaseStr(index, out_cc, env);
			out_cc->inc_indent();
			out_cc->println("%s = %s;", 
			                env->LValue(val_var),
			                c->value()->EvalExpr(out_cc, env));
			out_cc->println("break;");
			out_cc->dec_indent();
			}
		}

	// Generate the default case after all other cases
	GenCaseStr(0, out_cc, env);
	out_cc->inc_indent();
	if ( default_case )
		{
		out_cc->println("%s = %s;", 
	                	env->LValue(val_var),
		                default_case->value()->EvalExpr(out_cc, env));
		}
	else
		{
		out_cc->println("throw binpac::ExceptionInvalidCaseIndex(\"%s\", %s);",
			Location(), operand_[0]->EvalExpr(out_cc, env));
		}
	out_cc->println("break;");
	out_cc->dec_indent();

	out_cc->println("}");
	out_cc->dec_indent();

	env->SetEvaluated(val_var);
	str_ = env->RValue(val_var);
	}

void Expr::GenEval(Output* out_cc, Env* env)
	{
	switch ( expr_type_ )
		{
		case EXPR_NUM:
			str_ = num_->Str();
			break;

		case EXPR_ID:
			if ( ! env->Evaluated(id_) )
				env->Evaluate(out_cc, id_);
			str_ = env->RValue(id_);
			break;

		case EXPR_MEMBER:
			{
			/*
			For member expressions such X.Y, evaluating
			X only is sufficient. (Actually trying to
			evaluate Y will lead to error because Y is
			not defined in the current environment.)
			*/
			operand_[0]->GenEval(out_cc, env);

			Type *ty0 = operand_[0]->DataType(env);

			str_ = fmt("%s%s",
				operand_[0]->EvalExpr(out_cc, env),
				ty0 ? 
				ty0->EvalMember(operand_[1]->id()).c_str() :
				fmt("->%s()", operand_[1]->id()->Name()));
			}
			break;

		case EXPR_SUBSCRIPT:
			{
			operand_[0]->GenEval(out_cc, env);
			operand_[1]->GenEval(out_cc, env);

			string v0 = operand_[0]->EvalExpr(out_cc, env);
			string v1 = operand_[1]->EvalExpr(out_cc, env);
			
			Type *ty0 = operand_[0]->DataType(env);
			if ( ty0 )
				str_ = ty0->EvalElement(v0, v1);
			else
				str_ = fmt("%s[%s]", v0.c_str(), v1.c_str());
			}
			break;

		case EXPR_SIZEOF:
			{
			const ID *id = operand_[0]->id();
			RecordField *rf;
			Type *ty;

			try 
				{
				if ( (rf = GetRecordField(id, env)) != 0 )
					{
					str_ = fmt("%s", rf->FieldSize(out_cc, env));
					}
				}
			catch ( ExceptionIDNotFound &e )
				{
				if ( (ty = TypeDecl::LookUpType(id)) != 0 )
					{
					int ty_size = ty->StaticSize(global_env());
					if ( ty_size >= 0 )
						str_ = fmt("%d", ty_size);
					else
						throw Exception(id, "unknown size");
					}
				else
					throw Exception(id, "not a record field or type");
				}
			}
			break;

		case EXPR_OFFSETOF:
			{
			const ID *id = operand_[0]->id();
			RecordField *rf = GetRecordField(id, env);
			str_ = fmt("%s", rf->FieldOffset(out_cc, env));
			}
			break;

		case EXPR_CALLARGS:
			str_ = EvalExprList(args_, out_cc, env);
			break;

		case EXPR_CASE:
			GenCaseEval(out_cc, env);
			break;

		default:
			// Evaluate every operand by default
			for ( int i = 0; i < 3; ++i )
				if ( operand_[i] )
					operand_[i]->GenEval(out_cc, env);
			GenStrFromFormat(env);
			break;
		}
	}

void Expr::ForceIDEval(Output* out_cc, Env* env)
        {
	switch ( expr_type_ )
		{
		case EXPR_NUM:
		case EXPR_SIZEOF:
		case EXPR_OFFSETOF:
			break;

		case EXPR_ID:
			if ( ! env->Evaluated(id_) )
				env->Evaluate(out_cc, id_);
			break;

		case EXPR_MEMBER:
			operand_[0]->ForceIDEval(out_cc, env);
			break;

		case EXPR_CALLARGS:
		        {
		        foreach(i, ExprList, args_)
			        (*i)->ForceIDEval(out_cc, env);
			}
			break;

		case EXPR_CASE:
		        {
		        operand_[0]->ForceIDEval(out_cc, env);
			foreach(i, CaseExprList, cases_)
				(*i)->value()->ForceIDEval(out_cc, env);
		        }
			break;

		default:
			// Evaluate every operand by default
			for ( int i = 0; i < 3; ++i )
				if ( operand_[i] )
					operand_[i]->ForceIDEval(out_cc, env);
			break;
		}
	}


const char* Expr::EvalExpr(Output* out_cc, Env* env)
	{
	GenEval(out_cc, env);
	return str();
	}

Type *Expr::DataType(Env *env) const
	{
	Type *data_type;

	switch ( expr_type_ )
		{
		case EXPR_ID:
			data_type = env->GetDataType(id_);
			break;

		case EXPR_MEMBER:
			{
			// Get type of the parent
			Type *parent_type = operand_[0]->DataType(env);
			if ( ! parent_type )
				return 0;
			data_type = parent_type->MemberDataType(operand_[1]->id());
			}
			break;

		case EXPR_SUBSCRIPT:
			{
			// Get type of the parent
			Type *parent_type = operand_[0]->DataType(env);
			data_type = parent_type->ElementDataType();
			}
			break;

		case EXPR_PAREN:
			data_type = operand_[0]->DataType(env);
			break;

		case EXPR_COND:
			{
			Type *type1 = operand_[1]->DataType(env);
			Type *type2 = operand_[2]->DataType(env);
			if ( ! Type::CompatibleTypes(type1, type2) )
				{
				throw Exception(this, 
					fmt("type mismatch: %s vs %s",
					    type1->DataTypeStr().c_str(),
					    type2->DataTypeStr().c_str()));
				}
			data_type = type1;
			}
			break;

		case EXPR_CALL:
			data_type = operand_[0]->DataType(env);
			break;

		case EXPR_CASE:
			{
			if ( cases_ && ! cases_->empty() )
				{
				Type *type1 = 
					cases_->front()->value()->DataType(env);
				foreach(i, CaseExprList, cases_)
					{
					Type *type2 = 
						(*i)->value()->DataType(env);
					if ( ! Type::CompatibleTypes(type1, type2) )
						{
						throw Exception(this, 
							fmt("type mismatch: %s vs %s",
					    		    type1->DataTypeStr().c_str(),
					                    type2->DataTypeStr().c_str()));
						}
					if ( type1 == extern_type_nullptr )
						type1 = type2;
					}
				data_type = type1;
				}
			else
				data_type = 0;
			}
			break;

		case EXPR_NUM:
		case EXPR_SIZEOF:
		case EXPR_OFFSETOF:
		case EXPR_NEG:
		case EXPR_PLUS:
		case EXPR_MINUS:
		case EXPR_TIMES:
		case EXPR_DIV:
		case EXPR_MOD:
		case EXPR_BITNOT:
		case EXPR_BITAND:
		case EXPR_BITOR:
		case EXPR_BITXOR:
		case EXPR_LSHIFT:
		case EXPR_RSHIFT:
		case EXPR_EQUAL:
		case EXPR_GE:
		case EXPR_LE:
		case EXPR_GT:
		case EXPR_LT:
		case EXPR_NOT:
		case EXPR_AND:
		case EXPR_OR:
			data_type = extern_type_int;
			break;

		default:
			data_type = 0;
			break;
		}

	return data_type;
	}

string Expr::DataTypeStr(Env *env) const
	{
	Type *type = DataType(env);

	if ( ! type )
		{
		throw Exception(this, 
		                fmt("cannot find data type for expression `%s'",
		                    orig()));
		}

	return type->DataTypeStr();
	}

string Expr::SetFunc(Output *out, Env *env)
	{
	switch ( expr_type_ )
		{
		case EXPR_ID:
			return set_function(id_);
		case EXPR_MEMBER:
			{
			// Evaluate the parent
			string parent_val(operand_[0]->EvalExpr(out, env));
			return parent_val 
				+ "->" 
				+ set_function(operand_[1]->id());
			}
			break;
		default:
			throw Exception(this, 
			                fmt("cannot generate set function "
			                    "for expression `%s'", orig()));
			break;
		}
	}

bool Expr::ConstFold(Env* env, int* pn) const
	{
	switch ( expr_type_ ) 
		{
		case EXPR_NUM:	
			*pn = num_->Num();
			return true;
		case EXPR_ID:
			return env->GetConstant(id_, pn);
		default:	
			// ### FIXME: folding consts
			return false;
		}
	}

// TODO: build a generic data dependency extraction process
namespace {

	// Maximum of two minimal header sizes
	int mhs_max(int h1, int h2) 
		{
		if ( h1 < 0 || h2 < 0 )
			return -1;
		else
			{
			// return max(h1, h2);
			return h1 > h2 ? h1 : h2;
			}
		}
			
	// MHS required to evaluate the field
	int mhs_letfield(Env* env, LetField* field)
		{
		return field->expr()->MinimalHeaderSize(env);
		}

	int mhs_recordfield(Env* env, RecordField* field)
		{
		int offset = field->static_offset();
		if ( offset < 0 )  // offset cannot be statically determined
			return -1;
		int size = field->StaticSize(env, offset);
		if ( size < 0 )  // size cannot be statically determined
			return -1;
		return offset + size;
		}

	int mhs_casefield(Env* env, CaseField* field)
		{
		// TODO: deal with the index
		int size = field->StaticSize(env);
		if ( size < 0 )  // size cannot be statically determined
			return -1;
		return size;
		}

	int mhs_field(Env* env, Field* field)
		{
		int mhs = -1;
		switch ( field->tof() )
			{
			case LET_FIELD:
				{
				LetField *f = 
					static_cast<LetField *>(field);
				ASSERT(f);
				mhs = mhs_letfield(env, f);
				}
				break;

			case CONTEXT_FIELD:
			case FLOW_FIELD:
				ASSERT(0);
				break;

			case PARAM_FIELD:
				mhs = 0;
				break;

			case RECORD_FIELD:
			case PADDING_FIELD:
				{
				RecordField *f = 
					static_cast<RecordField *>(field);
				ASSERT(f);
				mhs = mhs_recordfield(env, f);
				}
				break;

			case CASE_FIELD:
				{
				CaseField *f = 
					static_cast<CaseField *>(field);
				ASSERT(f);
				mhs = mhs_casefield(env, f);
				}
				break;

			case PARSE_VAR_FIELD:
			case PRIV_VAR_FIELD:
			case PUB_VAR_FIELD:
			case TEMP_VAR_FIELD:
				mhs = 0;
				break;

			case WITHINPUT_FIELD:
				{
				// ### TODO: fix this
				mhs = -1;
				}
				break;
			}
		return mhs;
		}

	int mhs_id(Env *env, const ID *id)
		{
		int mhs = -1;
		switch ( env->GetIDType(id) ) 
			{
			case CONST:
			case GLOBAL_VAR:
			case TEMP_VAR:
			case STATE_VAR:
			case FUNC_ID:
			case FUNC_PARAM:
				mhs = 0;
				break;
			case MEMBER_VAR:
			case PRIV_MEMBER_VAR:
				{
				Field* field = env->GetField(id);
				if ( ! field )
					throw ExceptionIDNotField(id);
				mhs = mhs_field(env, field);
				}
				break;
			case UNION_VAR:
				// TODO: deal with UNION_VAR
				mhs = -1;
				break;
			case MACRO:
				{
				Expr *e = env->GetMacro(id);
				mhs = e->MinimalHeaderSize(env);
				}
				break;
			}
		return mhs;
		}
}

int Expr::MinimalHeaderSize(Env *env)
	{
	int mhs;

	switch ( expr_type_ )
		{
		case EXPR_NUM:
			// Zero byte is required
			mhs = 0;
			break;

		case EXPR_ID:
			mhs = mhs_id(env, id_);
			break;

		case EXPR_MEMBER:
			// TODO: this is not a tight bound because
			// one actually does not have to parse the
			// whole record to compute one particular
			// field.
			mhs = operand_[0]->MinimalHeaderSize(env);
			break;

		case EXPR_SUBSCRIPT:
			{
			int index;
			Type *array_type = operand_[0]->DataType(env);
			Type *elem_type = array_type->ElementDataType();
			int elem_size = elem_type->StaticSize(env);
			if ( elem_size >= 0 &&
			     operand_[1]->ConstFold(env, &index) )
				{
				mhs = elem_size * index;
				}
			else
				{
				mhs = -1;
				}
			}
			break;

		case EXPR_SIZEOF:
			{
			const ID* id = operand_[0]->id();
			ASSERT(id);
			RecordField *rf;
			Type *ty;

			if ( (rf = GetRecordField(id, env)) != 0 )
				{
				if ( rf->StaticSize(env, -1) >= 0 )
					mhs = 0;
				else
					mhs = mhs_recordfield(env, rf);
				}

			else if ( (ty = TypeDecl::LookUpType(id)) != 0 )
				{
				mhs = 0;
				}

			else
				throw Exception(id, "not a record field or type");
			}
			break;

		case EXPR_OFFSETOF:
			{
			const ID* id = operand_[0]->id();
			ASSERT(id);
			RecordField *field = GetRecordField(id, env);
			
			mhs = field->static_offset();
			if ( mhs < 0 )
				{
				mhs = 0;
				// Take the MHS of the preceding (non-let) field
				RecordField* prev_field = field->prev();
				ASSERT(prev_field);
				mhs = mhs_recordfield(env, prev_field);
				}
			}
			break;

		case EXPR_CALLARGS:
		        {
		        mhs = 0;
			if ( args_ )
			        for ( unsigned int i = 0; i < args_->size(); ++i )
					mhs = mhs_max(mhs, (*args_)[i]->MinimalHeaderSize(env));
			}
		        break;
		case EXPR_CASE:
		        {
		        mhs = operand_[0]->MinimalHeaderSize(env);
			for ( unsigned int i = 0; i < cases_->size(); ++i )
			        {
				CaseExpr * ce = (*cases_)[i];
				if ( ce->index() )
				        for ( unsigned int j = 0; j < ce->index()->size(); ++j )
						mhs = mhs_max(mhs, (*ce->index())[j]->MinimalHeaderSize(env));
				mhs = mhs_max(mhs, ce->value()->MinimalHeaderSize(env));
				}
			}
			break;
		default:
			// Evaluate every operand by default
			mhs = 0;
			for ( int i = 0; i < 3; ++i )
				if ( operand_[i] )
					mhs = mhs_max(mhs, operand_[i]->MinimalHeaderSize(env));
			break;
		}

	return mhs;
	}

bool Expr::HasReference(const ID *id) const
	{
	switch ( expr_type_ )
		{
		case EXPR_ID:
			return *id == *id_;

		case EXPR_MEMBER:
			return operand_[0]->HasReference(id);

		case EXPR_CALLARGS:
			{
			foreach(i, ExprList, args_)
				if ( (*i)->HasReference(id) )
					return true;
			}
			return false;

		case EXPR_CASE:
			{
			foreach(i, CaseExprList, cases_)
				if ( (*i)->HasReference(id) )
					return true;
			}
			return false;

		default:
			// Evaluate every operand by default
			for ( int i = 0; i < 3; ++i )
				{
				if ( operand_[i] && 
				     operand_[i]->HasReference(id) )
					{
					return true;
					}
				}
			return false;
		}
	}

bool Expr::DoTraverse(DataDepVisitor *visitor)
	{
	switch ( expr_type_ )
		{
		case EXPR_ID:
			break;

		case EXPR_MEMBER:
			/*
			For member expressions such X.Y, evaluating
			X only is sufficient. (Actually trying to
			evaluate Y will lead to error because Y is
			not defined in the current environment.)
			*/
			if ( ! operand_[0]->Traverse(visitor) )
				return false;
			break;

		case EXPR_CALLARGS:
			{
			foreach(i, ExprList, args_)
				if ( ! (*i)->Traverse(visitor) )
					return false;
			}
			break;

		case EXPR_CASE:
			{
			foreach(i, CaseExprList, cases_)
				if ( ! (*i)->Traverse(visitor) )
					return false;
			}
			break;

		default:
			// Evaluate every operand by default
			for ( int i = 0; i < 3; ++i )
				{
				if ( operand_[i] && 
				     ! operand_[i]->Traverse(visitor) )
					{
					return false;
					}
				}
			break;
		}

	return true;
	}

bool Expr::RequiresAnalyzerContext() const
	{
	switch ( expr_type_ )
		{
		case EXPR_ID:
			return *id_ == *analyzer_context_id;

		case EXPR_MEMBER:
			/*
			For member expressions such X.Y, evaluating
			X only is sufficient. (Actually trying to
			evaluate Y will lead to error because Y is
			not defined in the current environment.)
			*/
			return operand_[0]->RequiresAnalyzerContext();

		case EXPR_CALLARGS:
			{
			foreach(i, ExprList, args_)
				if ( (*i)->RequiresAnalyzerContext() )
					return true;
			}
			return false;

		case EXPR_CASE:
			{
			foreach(i, CaseExprList, cases_)
				if ( (*i)->RequiresAnalyzerContext() )
					return true;
			}
			return false;

		default:
			// Evaluate every operand by default
			for ( int i = 0; i < 3; ++i )
				if ( operand_[i] && 
				     operand_[i]->RequiresAnalyzerContext() )
					{
					DEBUG_MSG("'%s' requires analyzer context\n", operand_[i]->orig());
					return true;
					}
			return false;
		}
	}

CaseExpr::CaseExpr(ExprList *index, Expr *value)
	: DataDepElement(DataDepElement::CASEEXPR), 
	  index_(index), value_(value)
	{
	}

CaseExpr::~CaseExpr()
	{
	delete_list(ExprList, index_);
	delete value_;
	}

bool CaseExpr::DoTraverse(DataDepVisitor *visitor)
	{
	foreach(i, ExprList, index_)
		if ( ! (*i)->Traverse(visitor) )
			return false;
	return value_->Traverse(visitor);
	}

bool CaseExpr::HasReference(const ID *id) const
	{
	return value_->HasReference(id);
	}

bool CaseExpr::RequiresAnalyzerContext() const
	{
	// index_ should evaluate to constants
	return value_->RequiresAnalyzerContext();
	}
