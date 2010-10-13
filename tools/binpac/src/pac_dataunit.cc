#include "pac_context.h"
#include "pac_dataunit.h"
#include "pac_output.h"
#include "pac_paramtype.h"
#include "pac_varfield.h"

AnalyzerDataUnit::AnalyzerDataUnit(
		DataUnitType type, 
		ID *id, 
		ExprList *type_params,
		ExprList *context_params)
	: AnalyzerElement(DATAUNIT),
	  type_(type),
	  id_(id),
	  type_params_(type_params),
	  context_params_(context_params) 
	{
	data_type_ = new ParameterizedType(id_, type_params_);
	context_type_ = new ParameterizedType(
		AnalyzerContextDecl::current_analyzer_context()->id()->clone(),
		context_params_);

	dataunit_var_field_ = new ParseVarField(
		Field::CLASS_MEMBER,
		dataunit_id->clone(),
		data_type());
	context_var_field_ = new PrivVarField(
		analyzer_context_id->clone(),
		context_type());
	}

AnalyzerDataUnit::~AnalyzerDataUnit()
	{
	delete dataunit_var_field_;
	delete context_var_field_;
	}

void AnalyzerDataUnit::Prepare(Env *env)
	{
	dataunit_var_field_->Prepare(env);
	context_var_field_->Prepare(env);
	}

void AnalyzerDataUnit::GenNewDataUnit(Output *out_cc, Env *env)
	{
	out_cc->println("%s = new %s(%s);",
		env->LValue(dataunit_id),
		data_type()->class_name().c_str(),
		data_type()->EvalParameters(out_cc, env).c_str());
	}

void AnalyzerDataUnit::GenNewContext(Output *out_cc, Env *env)
	{
	out_cc->println("%s = new %s(%s);", 
		env->LValue(analyzer_context_id),
		context_type()->class_name().c_str(),
		context_type()->EvalParameters(out_cc, env).c_str());
	env->SetEvaluated(analyzer_context_id);
	}

