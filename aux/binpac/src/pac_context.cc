#include "pac_analyzer.h"
#include "pac_exception.h"
#include "pac_exttype.h"
#include "pac_flow.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_paramtype.h"
#include "pac_type.h"
#include "pac_utils.h"

#include "pac_context.h"

ContextField::ContextField(ID *id, Type *type)
	: Field(CONTEXT_FIELD, 
		TYPE_NOT_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE, 
		id, type)
	{
	}

AnalyzerContextDecl *AnalyzerContextDecl::current_analyzer_context_ = 0;

namespace {
	ParamList *ContextFieldsToParams(ContextFieldList *context_fields)
		{
		// Convert context fields to parameters
		ParamList *params = new ParamList();
		foreach(i, ContextFieldList, context_fields)
			{
			ContextField *f = *i;
			params->push_back(
				new Param(f->id()->clone(), 
				f->type()));
			}
		return params;
		}
} // namespace private

AnalyzerContextDecl::AnalyzerContextDecl(
		ID *id, 
		ContextFieldList *context_fields)
	: TypeDecl(new ID(fmt("Context%s", id->Name())), 
		ContextFieldsToParams(context_fields), 
		new DummyType())
	{
	context_name_id_ = id;
	if ( current_analyzer_context_ != 0 )
		{
		throw Exception(this, 
		                fmt("multiple declaration of analyzer context; "
		                    "the previous one is `%s'",
		                    current_analyzer_context_->id()->Name()));
		}
	else
		current_analyzer_context_ = this;

	context_fields_ = context_fields;

	param_type_ = new ParameterizedType(id_->clone(), 0);

	flow_buffer_added_ = false;

	DEBUG_MSG("Context type: %s\n", param_type()->class_name().c_str());
	}

AnalyzerContextDecl::~AnalyzerContextDecl()
	{
	delete context_name_id_;
	delete_list(ContextFieldList, context_fields_);
	}

void AnalyzerContextDecl::GenForwardDeclaration(Output *out_h)
	{
	GenNamespaceBegin(out_h);
	TypeDecl::GenForwardDeclaration(out_h);
	}

void AnalyzerContextDecl::GenCode(Output *out_h, Output *out_cc)
	{
	GenNamespaceBegin(out_h);
	GenNamespaceBegin(out_cc);
	TypeDecl::GenCode(out_h, out_cc);
	}

void AnalyzerContextDecl::GenNamespaceBegin(Output *out) const
	{
	out->println("namespace %s {", context_name_id()->Name());
	}

void AnalyzerContextDecl::GenNamespaceEnd(Output *out) const
	{
	out->println("} // namespace %s", context_name_id()->Name());
	}

void AnalyzerContextDecl::AddFlowBuffer()
	{
	if ( flow_buffer_added_ )
		return;

	AddParam(new Param(
		new ID(kFlowBufferVar), 
		FlowDecl::flow_buffer_type()->Clone()));

	flow_buffer_added_ = true;
	}

string AnalyzerContextDecl::mb_buffer(Env *env)
	{
	// A hack. The orthodox way would be to build an Expr of
	// context.flow_buffer_var, and then EvalExpr.
	return fmt("%s->%s()", 
		env->RValue(analyzer_context_id), 
		kFlowBufferVar);
	}

Type *DummyType::DoClone() const
	{
	// Fields will be copied in Type::Clone().
	return new DummyType();
	}
