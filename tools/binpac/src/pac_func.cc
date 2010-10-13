#include "pac_embedded.h"
#include "pac_expr.h"
#include "pac_func.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_type.h"

Function::Function(ID *id, Type *type, ParamList *params)
 	: id_(id), type_(type), params_(params), expr_(0), code_(0)
	{
	analyzer_decl_ = 0;
	env_ = 0;
	}

Function::~Function()
	{
	delete id_;
	delete type_;
	delete_list(ParamList, params_);
	delete env_;
	delete expr_;
	delete code_;
	}

void Function::Prepare(Env *env)
	{
	env->AddID(id_, FUNC_ID, type_);
	env->SetEvaluated(id_);

	env_ = new Env(env, this);

	foreach(i, ParamList, params_)
		{
		Param *p = *i;
		env_->AddID(p->id(), FUNC_PARAM, p->type());
		env_->SetEvaluated(p->id());
		}
	}

void Function::GenForwardDeclaration(Output* out_h)
	{
	// Do nothing
	}

void Function::GenCode(Output* out_h, Output* out_cc)
	{
	out_h->println("%s %s(%s);", 
		type_->DataTypeStr().c_str(),
		id_->Name(),
		ParamDecls(params_).c_str());

	string class_str = "";
	if ( analyzer_decl_ )
		class_str = strfmt("%s::", analyzer_decl_->id()->Name());

	string proto_str = strfmt("%s %s%s(%s)", 
				type_->DataTypeStr().c_str(),
				class_str.c_str(),
				id_->Name(),
				ParamDecls(params_).c_str());

	ASSERT(!(expr_ && code_));

	if ( expr_ )
		{
		out_cc->println("%s", proto_str.c_str());

		out_cc->inc_indent();
		out_cc->println("{");

		out_cc->println("return static_cast<%s>(%s);", 
			type_->DataTypeStr().c_str(),
			expr_->EvalExpr(out_cc, env_));

		out_cc->println("}");
		out_cc->dec_indent();
		}

	else if ( code_ )
		{
		out_cc->println("%s", proto_str.c_str());

		out_cc->inc_indent();
		out_cc->println("{");

		code_->GenCode(out_cc, env_);

		out_cc->println("}");
		out_cc->dec_indent();
		}

	out_cc->println("");
	}

FuncDecl::FuncDecl(Function *function)
	: Decl(function->id()->clone(), FUNC), function_(function)
	{
	function_->Prepare(global_env());
	}

FuncDecl::~FuncDecl()
	{
	delete function_;
	}

void FuncDecl::Prepare()
	{
	}

void FuncDecl::GenForwardDeclaration(Output *out_h)
	{
	function_->GenForwardDeclaration(out_h);
	}

void FuncDecl::GenCode(Output *out_h, Output *out_cc)
	{
	function_->GenCode(out_h, out_cc);
	}

AnalyzerFunction::AnalyzerFunction(Function *function)
	: AnalyzerElement(FUNCTION), function_(function)
	{
	}
