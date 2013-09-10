#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_let.h"
#include "pac_output.h"
#include "pac_type.h"

namespace {

void GenLetEval(const ID *id, Expr *expr, string prefix, Output* out, Env* env)
	{
	if ( expr )
		{
		}
	}

} // private namespace

LetField::LetField(ID* id, Type *type, Expr* expr)
	: Field(LET_FIELD, 
		TYPE_NOT_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE, 
		id, type), 
	  expr_(expr)
	{
	ASSERT(expr_);
	}

LetField::~LetField()
	{
	delete expr_;
	}

bool LetField::DoTraverse(DataDepVisitor *visitor)
	{ 
	return Field::DoTraverse(visitor) &&
	       expr()->Traverse(visitor); 
	}

bool LetField::RequiresAnalyzerContext() const 
	{ 
	return Field::RequiresAnalyzerContext() ||
	       (expr() && expr()->RequiresAnalyzerContext()); 
	}

void LetField::Prepare(Env* env)
	{
	if ( ! type_ )
		{
		ASSERT(expr_);
		type_ = expr_->DataType(env);
		if ( type_ )
			type_ = type_->Clone();		
		else
			type_ = extern_type_int->Clone();

		foreach(i, AttrList, attrs_)
			ProcessAttr(*i);
		}

	Field::Prepare(env);
	env->SetEvalMethod(id_, this);
	}

void LetField::GenInitCode(Output* out_cc, Env* env)
	{
	int v;
	if ( expr_ && expr_->ConstFold(env, &v) )
		{
		DEBUG_MSG("Folding const for `%s'\n", id_->Name());
		GenEval(out_cc, env);
		}
	else
		type_->GenInitCode(out_cc, env);
	}

void LetField::GenParseCode(Output* out_cc, Env* env)
	{
	if ( env->Evaluated(id_) )
		return;

	if ( type_->attr_if_expr() )
		{
		// A conditional field

		env->Evaluate(out_cc, type_->has_value_var());

		// force evaluation of IDs contained in this expr
		expr()->ForceIDEval(out_cc, env);

		out_cc->println("if ( %s )", 
			env->RValue(type_->has_value_var()));
		out_cc->inc_indent();
		out_cc->println("{");
		}

	out_cc->println("%s = %s;", 
		env->LValue(id_), 
	       	expr()->EvalExpr(out_cc, env));
	if ( ! env->Evaluated(id_) )
		env->SetEvaluated(id_);

	if ( type_->attr_if_expr() )
		{
		out_cc->println("}");
		out_cc->dec_indent();
		}
	}

void LetField::GenEval(Output* out_cc, Env* env)
	{
	GenParseCode(out_cc, env);
	}

LetDecl::LetDecl(ID *id, Type *type, Expr *expr)
 	: Decl(id, LET), type_(type), expr_(expr)
	{
	if ( ! type_ )
		{
		ASSERT(expr_);
	        type_ = expr_->DataType(global_env());
		if ( type_ )
			type_ = type_->Clone();		
		else
			type_ = extern_type_int->Clone();
		}

	Env *env = global_env();
	int c;
	if ( expr_ && expr_->ConstFold(env, &c) )
		env->AddConstID(id_, c);
	else
		env->AddID(id_, GLOBAL_VAR, type_);
	}

LetDecl::~LetDecl()
	{
	delete type_;
	delete expr_;
	}

void LetDecl::Prepare()
	{
	}

void LetDecl::GenForwardDeclaration(Output* out_h)
	{
	}

void LetDecl::GenCode(Output * out_h, Output *out_cc)
	{
	out_h->println("extern %s const %s;",
		type_->DataTypeStr().c_str(),
		global_env()->RValue(id_));
	GenEval(out_cc, global_env());
	}

void LetDecl::GenEval(Output *out_cc, Env * /* env */)
	{
	Env *env = global_env();
	out_cc->println("%s %s = %s;", 
		fmt("%s const", type_->DataTypeStr().c_str()),
		env->LValue(id_), 
	       	expr_->EvalExpr(out_cc, env));

	if ( ! env->Evaluated(id_) )
		env->SetEvaluated(id_);
	}
