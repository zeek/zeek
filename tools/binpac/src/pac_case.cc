#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_typedecl.h"
#include "pac_utils.h"
#include "pac_btype.h"

#include "pac_case.h"

#include <limits>
#include <stdint.h>

CaseType::CaseType(Expr* index_expr, CaseFieldList* cases)
	: Type(CASE), index_expr_(index_expr), cases_(cases) 
	{
	index_var_ = 0;
	foreach(i, CaseFieldList, cases_)
		AddField(*i);
	}

CaseType::~CaseType()
	{
	delete index_var_;
	delete index_expr_;
	delete cases_;
	}

void CaseType::AddCaseField(CaseField *f)
	{
	// All fields must be added before Prepare()
	ASSERT(!env());

	AddField(f);
	cases_->push_back(f);
	}

bool CaseType::DefineValueVar() const
	{
	return false;
	}

string CaseType::DataTypeStr() const
	{
	ASSERT(type_decl());
	return strfmt("%s *", type_decl()->class_name().c_str());
	}

Type *CaseType::ValueType() const
	{
	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		return c->type();
		}
	ASSERT(0);
	return 0;
	}

string CaseType::DefaultValue() const
	{
	return ValueType()->DefaultValue();
	}

void CaseType::Prepare(Env* env, int flags)
	{
	ASSERT(flags & TO_BE_PARSED);

	index_var_ = new ID(strfmt("%s_case_index", value_var()->Name()));
	// Unable to get the type for index_var_ at this moment, but we'll
	// generate the right type based on index_expr_ later.
	env->AddID(index_var_, MEMBER_VAR, 0);

	// Sort the cases_ to put the default case at the end of the list
	CaseFieldList::iterator default_case_it = 
		cases_->end(); // to avoid warning
	CaseField *default_case = 0;

	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		if ( ! c->index() )
			{
			if ( default_case )
				throw Exception(c, "duplicate default case");
			default_case_it = i;
			default_case = c;
			}
		}
	if ( default_case )
		{
		cases_->erase(default_case_it);
		cases_->push_back(default_case);
		}

	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		c->set_index_var(index_var_);
		c->set_case_type(this);
		}

	Type::Prepare(env, flags);
	}

void CaseType::GenPrivDecls(Output* out_h, Env* env)
	{
	Type* t = index_expr_->DataType(env);

	if ( t->tot() != Type::BUILTIN )
		// It's a Type::EXTERN with a C++ type of "int", "bool", or "enum",
		// any of which will convert consistently using an int as storage type.
		t = extern_type_int;

	out_h->println("%s %s;", t->DataTypeStr().c_str(), env->LValue(index_var_));
	Type::GenPrivDecls(out_h, env);
	}

void CaseType::GenPubDecls(Output* out_h, Env* env)
	{
	Type* t = index_expr_->DataType(env);

	if ( t->tot() != Type::BUILTIN )
		t = extern_type_int;

	out_h->println("%s %s const	{ return %s; }", t->DataTypeStr().c_str(),
		env->RValue(index_var_), env->LValue(index_var_));
	Type::GenPubDecls(out_h, env);
	}

void CaseType::GenInitCode(Output* out_cc, Env* env)
	{
	out_cc->println("%s = -1;", env->LValue(index_var_));
	Type::GenInitCode(out_cc, env);
	}

void CaseType::GenCleanUpCode(Output* out_cc, Env* env)
	{
	Type::GenCleanUpCode(out_cc, env);

	env->set_in_branch(true);
	out_cc->println("switch ( %s )", env->RValue(index_var_));
	out_cc->inc_indent();
	out_cc->println("{");
	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		c->GenCleanUpCode(out_cc, env);
		}
	out_cc->println("}");
	out_cc->dec_indent();
	env->set_in_branch(false);
	}

void CaseType::DoGenParseCode(Output* out_cc, Env* env,
		const DataPtr& data, int flags)
	{
	if ( StaticSize(env) >= 0 )
		GenBoundaryCheck(out_cc, env, data);

	bool compute_size_var = false;

	if ( ! incremental_input() )
		compute_size_var = AddSizeVar(out_cc, env);

	out_cc->println("%s = %s;", 
		env->LValue(index_var_), index_expr_->EvalExpr(out_cc, env));
	env->SetEvaluated(index_var_);
	
	env->set_in_branch(true);
	out_cc->println("switch ( %s )", env->RValue(index_var_));
	out_cc->inc_indent();
	out_cc->println("{");
	bool has_default_case = false;
	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		c->GenParseCode(out_cc, env, data, 
			compute_size_var ? size_var() : 0);
		if ( c->IsDefaultCase() )
			has_default_case = true;
		}

	if ( ! has_default_case )
		{
		out_cc->println("default:");
		out_cc->inc_indent();
		out_cc->println("throw binpac::ExceptionInvalidCaseIndex(\"%s\", (int64)%s);",
			decl_id()->Name(), env->RValue(index_var_));
		out_cc->println("break;");
		out_cc->dec_indent();
		}
	out_cc->println("}");
	out_cc->dec_indent();
	env->set_in_branch(false);

	if ( compute_size_var )
		env->SetEvaluated(size_var());
	}

void CaseType::GenDynamicSize(Output* out_cc, Env* env,
		const DataPtr& data)
	{
	GenParseCode(out_cc, env, data, 0);
	}

int CaseType::StaticSize(Env* env) const
	{
	int static_w = -1;
	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		int w = c->StaticSize(env);
		if ( w < 0 || ( static_w >= 0 && w != static_w ) )
			return -1;
		static_w = w;
		}
	return static_w;
	}

void CaseType::SetBoundaryChecked()
	{
	Type::SetBoundaryChecked();
	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		c->SetBoundaryChecked();
		}
	}

void CaseType::DoMarkIncrementalInput()
	{
	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		c->type()->MarkIncrementalInput();
		}
	}

bool CaseType::ByteOrderSensitive() const
	{
	foreach (i, CaseFieldList, cases_)
		{
		CaseField *c = *i;
		if ( c->RequiresByteOrder() )
			return true;
		}
	return false;
	}

CaseField::CaseField(ExprList* index, ID* id, Type* type)
	: Field(CASE_FIELD, 
		TYPE_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE, 
		id, type), 
	  index_(index)
	{
	ASSERT(type_);
	type_->set_value_var(id, MEMBER_VAR);
	case_type_ = 0;
	index_var_ = 0;
	}

CaseField::~CaseField()
	{
	delete_list(ExprList, index_);
	}

void GenCaseStr(ExprList *index_list, Output *out_cc, Env *env, Type* switch_type)
	{
	if ( index_list )
		{
		foreach(i, ExprList, index_list)
			{
			Expr *index_expr = *i;

			Type* case_type = index_expr->DataType(env);

			if ( case_type->tot() == Type::BUILTIN && case_type->StaticSize(env) > 4 )
				throw ExceptionInvalidCaseSizeExpr(index_expr);

			int index_const;
			
			if ( ! index_expr->ConstFold(env, &index_const) )
				throw ExceptionNonConstExpr(index_expr);

			// External C++ types like "int", "bool", "enum"
			// all use "int" type internally by default.
			int case_type_width = 4;
			int switch_type_width = 4;

			if ( switch_type->tot() == Type::BUILTIN )
				switch_type_width = switch_type->StaticSize(env);

			if ( case_type->tot() == Type::BUILTIN )
				case_type_width = case_type->StaticSize(env);

			if ( case_type_width > switch_type_width )
				{
				BuiltInType* st = (BuiltInType*)switch_type;

				if ( switch_type_width == 1 )
					{
					if ( st->bit_type() == BuiltInType::INT8 )
						{
						if ( index_const < std::numeric_limits<int8_t>::min() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						if ( index_const > std::numeric_limits<int8_t>::max() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						}
					else
						{
						if ( index_const < std::numeric_limits<uint8_t>::min() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						if ( index_const > std::numeric_limits<uint8_t>::max() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						}
					}
				else if ( switch_type_width == 2 )
					{
					if ( st->bit_type() == BuiltInType::INT16 )
						{
						if ( index_const < std::numeric_limits<int16_t>::min() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						if ( index_const > std::numeric_limits<int16_t>::max() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						}
					else
						{
						if ( index_const < std::numeric_limits<uint16_t>::min() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						if ( index_const > std::numeric_limits<uint16_t>::max() )
							throw ExceptionInvalidCaseLimitExpr(index_expr);
						}
					}
				}

			// We're always using "int" for storage, so ok to just
			// cast into the type used by the switch statement since
			// some unsafe stuff is already checked above.
			out_cc->println("case ((%s) %d):",
			                switch_type->DataTypeStr().c_str(), index_const);
			}
		}
	else
		{
		out_cc->println("default:");
		}
	}

void CaseField::Prepare(Env* env)
	{
	ASSERT(index_var_);
	Field::Prepare(env);
	}

void CaseField::GenPubDecls(Output* out_h, Env* env)
	{
	if ( ! ((flags_ & PUBLIC_READABLE) && (flags_ & CLASS_MEMBER)) )
		return;

	// Skip type "empty"
	if ( type_->DataTypeStr().empty() )
		return;

	out_h->println("%s %s const",
		type_->DataTypeConstRefStr().c_str(), env->RValue(id_));

	out_h->inc_indent();
	out_h->println("{");

	if ( ! index_ )
		out_h->println("return %s;", lvalue());
	else
		{
		out_h->println("switch ( %s )", env->RValue(index_var_));
		out_h->inc_indent();
		out_h->println("{");
		GenCaseStr(index_, out_h, env, case_type()->IndexExpr()->DataType(env));
		out_h->inc_indent();
		out_h->println("break;  // OK");
		out_h->dec_indent();

		out_h->println("default:");
		out_h->inc_indent();
		out_h->println(
			"throw binpac::ExceptionInvalidCase(\"%s\", (int64)%s, \"%s\");",
			id_->LocName(),
			env->RValue(index_var_),
			OrigExprList(index_).c_str());
		out_h->println("break;");
		out_h->dec_indent();

		out_h->println("}");
		out_h->dec_indent();

		out_h->println("return %s;", lvalue());
		}

	out_h->println("}");
	out_h->dec_indent();
	}

void CaseField::GenInitCode(Output* out_cc, Env* env)
	{
	// GenCaseStr(index_, out_cc, env);
	// out_cc->inc_indent();
	// out_cc->println("{");
	// out_cc->println("// Initialize \"%s\"", id_->Name());
	type_->GenInitCode(out_cc, env);
	// out_cc->println("}");
	// out_cc->println("break;");
	// out_cc->dec_indent();
	}

void CaseField::GenCleanUpCode(Output* out_cc, Env* env)
	{
	GenCaseStr(index_, out_cc, env, case_type()->IndexExpr()->DataType(env));
	out_cc->inc_indent();
	out_cc->println("// Clean up \"%s\"", id_->Name());
	out_cc->println("{");
	if ( ! anonymous_field() )
		type_->GenCleanUpCode(out_cc, env);
	out_cc->println("}");
	out_cc->println("break;");
	out_cc->dec_indent();
	}

void CaseField::GenParseCode(Output* out_cc, Env* env, 
		const DataPtr& data, const ID* size_var)
	{
	GenCaseStr(index_, out_cc, env, case_type()->IndexExpr()->DataType(env));
	out_cc->inc_indent();
	out_cc->println("// Parse \"%s\"", id_->Name());
	out_cc->println("{");
	
	{
	Env case_env(env, this);

	type_->GenPreParsing(out_cc, &case_env);
	type_->GenParseCode(out_cc, &case_env, data, 0);
	if ( size_var )
		{
		out_cc->println("%s = %s;",
			case_env.LValue(size_var),
			type_->DataSize(out_cc, &case_env, data).c_str());
		}
	if ( type_->incremental_input() )
		{
		ASSERT(case_type()->parsing_complete_var());
		out_cc->println("%s = %s;",
			case_env.LValue(case_type()->parsing_complete_var()),
			case_env.RValue(type_->parsing_complete_var()));
		}
	out_cc->println("}");
	}

	out_cc->println("break;");
	out_cc->dec_indent();
	}

bool CaseField::DoTraverse(DataDepVisitor *visitor)
	{ 
	return Field::DoTraverse(visitor) &&
	       type()->Traverse(visitor); 
	}

bool CaseField::RequiresAnalyzerContext() const 
	{ 
	return Field::RequiresAnalyzerContext() ||
	       type()->RequiresAnalyzerContext(); 
	}
