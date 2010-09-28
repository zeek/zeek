#include "pac_withinput.h"
#include "pac_dataptr.h"
#include "pac_expr.h"
#include "pac_inputbuf.h"
#include "pac_output.h"
#include "pac_type.h"

WithInputField::WithInputField(ID* id, Type *type, InputBuffer* input)
	: Field(WITHINPUT_FIELD, 
		TYPE_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE, 
		id, type), 
	  input_(input)
	{
	ASSERT(type_);
	ASSERT(input_);
	}

WithInputField::~WithInputField()
	{
	delete input_;
	}

bool WithInputField::DoTraverse(DataDepVisitor *visitor)
	{ 
	return Field::DoTraverse(visitor) &&
	       input()->Traverse(visitor); 
	}

bool WithInputField::RequiresAnalyzerContext() const 
	{ 
	return Field::RequiresAnalyzerContext() ||
	       (input() && input()->RequiresAnalyzerContext()); 
	}

void WithInputField::Prepare(Env* env)
	{
	Field::Prepare(env);
	env->SetEvalMethod(id_, this);
	}

void WithInputField::GenEval(Output* out_cc, Env* env)
	{
	GenParseCode(out_cc, env);
	if ( type_->attr_if_expr() )
		{
		out_cc->println("BINPAC_ASSERT(%s);", 
			env->RValue(type_->has_value_var()));
		}
	}
	
void WithInputField::GenParseCode(Output* out_cc, Env* env)
	{
	out_cc->println("// Parse \"%s\"", id_->Name());
	if ( type_->attr_if_expr() )
		{
		// A conditional field
		env->Evaluate(out_cc, type_->has_value_var());
		out_cc->println("if ( %s )", 
			env->RValue(type_->has_value_var()));
		out_cc->inc_indent();
		out_cc->println("{");
		}
	else
		out_cc->println("{");

	Env field_env(env, this);
	ASSERT(! type_->incremental_input());
	type_->GenPreParsing(out_cc, &field_env);
	type_->GenParseCode(out_cc, &field_env, 
		input()->GenDataBeginEnd(out_cc, &field_env),
		0);

	if ( type_->attr_if_expr() )
		{
		out_cc->println("}");
		out_cc->dec_indent();
		}
	else
		out_cc->println("}");
	}
