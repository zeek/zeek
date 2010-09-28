#include "pac_embedded.h"
#include "pac_exception.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_type.h"
#include "pac_typedecl.h"
#include "pac_utils.h"

#include "pac_action.h"

AnalyzerAction::AnalyzerAction(ID *action_id, 
	                       When when, 
	                       ActionParam *param, 
	                       EmbeddedCode *code)
	: AnalyzerElement(ACTION),
	  action_id_(action_id),
	  when_(when),
	  param_(param),
	  code_(code),
	  analyzer_(0) 
	{
	}

AnalyzerAction::~AnalyzerAction()
	{
	delete action_id_;
	delete param_;
	delete code_;
	}

string AnalyzerAction::action_function() const
	{
	return strfmt("Action_%s", action_id_->Name());
	}

void AnalyzerAction::InstallHook(AnalyzerDecl *analyzer)
	{
	ASSERT(0);
	analyzer_ = analyzer;
	// param_->MainDataType()->InstallAction(this);
	}

void AnalyzerAction::GenCode(Output *out_h, Output *out_cc, AnalyzerDecl *decl)
	{
	Env action_func_env(decl->env(), this);
	action_func_env.AddID(param_->id(), 
	                      TEMP_VAR, 
	                      param_->DataType());
	action_func_env.SetEvaluated(param_->id());

	string action_func_proto = 
		strfmt("%s(%s)", 
		       action_function().c_str(), 
		       ParamDecls(&action_func_env).c_str());

	out_h->println("void %s;", action_func_proto.c_str());

	out_cc->println("void %s::%s", 
	                decl->class_name().c_str(), 
	                action_func_proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	code_->GenCode(out_cc, &action_func_env);

	out_cc->println("");
	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("");
	}

string AnalyzerAction::ParamDecls(Env *env) const
	{
	return param_->DeclStr(env);
	}

Type *ActionParam::MainDataType() const
	{
	// Note: this is not equal to DataType()
	Type *main_type = TypeDecl::LookUpType(type()->type_id());

	if ( ! main_type )
		{
		throw Exception(type()->type_id(), 
		                "type not defined");
		}

	return main_type;
	}

Type *ActionParam::DataType() const
	{
	Type *main_type = MainDataType();

	if ( ! type()->field_id() )
		{
		return main_type;
		}
	else
		{
		Type *member_type = 
			main_type->MemberDataType(type()->field_id());
		if ( ! member_type )
			{
			throw Exception(type()->field_id(),
				fmt("cannot find member type for `%s.%s'",
				    type()->type_id()->Name(),
				    type()->field_id()->Name()));
			}
		return member_type;
		}
	}

string ActionParam::DeclStr(Env *env) const
	{
	return strfmt("%s %s", 
	              DataType()->DataTypeStr().c_str(), 
	              env->LValue(id()));
	}
