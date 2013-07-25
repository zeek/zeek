#include "pac_analyzer.h"
#include "pac_conn.h"
#include "pac_context.h"
#include "pac_dataptr.h"
#include "pac_dataunit.h"
#include "pac_embedded.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_flow.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_paramtype.h"
#include "pac_type.h"
#include "pac_varfield.h"


FlowDecl::FlowDecl(ID *id, 
                   ParamList *params, 
                   AnalyzerElementList *elemlist)
	: AnalyzerDecl(id, FLOW, params)
	{
	dataunit_ = 0;
	conn_decl_ = 0;
	flow_buffer_var_field_ = 0;
	AddElements(elemlist);
	}

FlowDecl::~FlowDecl()
	{
	delete flow_buffer_var_field_;
	delete dataunit_;
	}

ParameterizedType *FlowDecl::flow_buffer_type_ = 0;

ParameterizedType *FlowDecl::flow_buffer_type()
	{
	if ( ! flow_buffer_type_ )
		{
		flow_buffer_type_ = new ParameterizedType(new ID(kFlowBufferClass), 0);
		}
	return flow_buffer_type_;
	}

void FlowDecl::AddBaseClass(vector<string> *base_classes) const
	{
	base_classes->push_back("binpac::FlowAnalyzer"); 
	} 

void FlowDecl::ProcessFlowElement(AnalyzerFlow *flow_elem)
	{
	throw Exception(
		flow_elem, 
		"flow should be defined in only a connection declaration");
	}

void FlowDecl::ProcessDataUnitElement(AnalyzerDataUnit *dataunit_elem)
	{
	if ( dataunit_ )
		{
		throw Exception(dataunit_elem,
		                "dataunit already defined");
		}
	dataunit_ = dataunit_elem;

	if ( dataunit_->type() == AnalyzerDataUnit::FLOWUNIT )
		{
		dataunit_->data_type()->MarkIncrementalInput();

		flow_buffer_var_field_ = new PubVarField(
			flow_buffer_id->clone(),
			FlowDecl::flow_buffer_type()->Clone());
		type_->AddField(flow_buffer_var_field_);

		ASSERT(AnalyzerContextDecl::current_analyzer_context());
		AnalyzerContextDecl::current_analyzer_context()->AddFlowBuffer();

		// Add an argument to the context initiation
		dataunit_->context_type()->AddParamArg(
			new Expr(flow_buffer_var_field_->id()->clone()));
		}
	}

void FlowDecl::Prepare()
	{
	// Add the connection parameter
	if ( ! conn_decl_ )
		{
		throw Exception(this, 
		                "no connection is not declared for the flow");
		}

	if ( ! params_ )
		params_ = new ParamList();

	params_->insert(params_->begin(),
	                new Param(connection_id->clone(), 
	                          conn_decl_->DataType()));

	AnalyzerDecl::Prepare();

	dataunit_->Prepare(env_);
	}

void FlowDecl::GenPubDecls(Output *out_h, Output *out_cc)
	{
	AnalyzerDecl::GenPubDecls(out_h, out_cc);
	}

void FlowDecl::GenPrivDecls(Output *out_h, Output *out_cc)
	{
	// Declare the data unit
	dataunit_->dataunit_var_field()->GenPrivDecls(out_h, env_);

	// Declare the analyzer context
	dataunit_->context_var_field()->GenPrivDecls(out_h, env_);

	AnalyzerDecl::GenPrivDecls(out_h, out_cc);
	}

void FlowDecl::GenInitCode(Output *out_cc)
	{
	AnalyzerDecl::GenInitCode(out_cc);

	out_cc->println("%s = 0;",
	                env_->LValue(dataunit_id));
	out_cc->println("%s = 0;",
	                env_->LValue(analyzer_context_id));

	if ( dataunit_->type() == AnalyzerDataUnit::FLOWUNIT )
		{
		flow_buffer_var_field_->type()->GenPreParsing(out_cc, env_);
		env_->SetEvaluated(flow_buffer_var_field_->id());
		}
	}

void FlowDecl::GenCleanUpCode(Output *out_cc)
	{
	GenDeleteDataUnit(out_cc);
	AnalyzerDecl::GenCleanUpCode(out_cc);
	}

void FlowDecl::GenEOFFunc(Output *out_h, Output *out_cc)
	{
	string proto = strfmt("%s()", kFlowEOF);

	out_h->println("void %s;", proto.c_str());

	out_cc->println("void %s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	foreach(i, AnalyzerHelperList, eof_helpers_)
		{
		(*i)->GenCode(0, out_cc, this);
		}

	if ( dataunit_->type() == AnalyzerDataUnit::FLOWUNIT )
		{
		out_cc->println("%s->set_eof();", 
			env_->LValue(flow_buffer_id));
		out_cc->println("%s(0, 0);", kNewData);
		}
	
	out_cc->println("}");
	out_cc->dec_indent();
	}

void FlowDecl::GenGapFunc(Output *out_h, Output *out_cc)
	{
	string proto = strfmt("%s(int gap_length)", kFlowGap);

	out_h->println("void %s;", proto.c_str());

	out_cc->println("void %s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	if ( dataunit_->type() == AnalyzerDataUnit::FLOWUNIT )
		{
		out_cc->println("%s->NewGap(gap_length);", 
			env_->LValue(flow_buffer_id));
		}
	
	out_cc->println("}");
	out_cc->dec_indent();
	}

void FlowDecl::GenProcessFunc(Output *out_h, Output *out_cc)
	{
	env_->AddID(begin_of_data, TEMP_VAR, extern_type_const_byteptr);
	env_->AddID(end_of_data, TEMP_VAR, extern_type_const_byteptr);

	string proto = 
		strfmt("%s(const_byteptr %s, const_byteptr %s)",
			kNewData,
			env_->LValue(begin_of_data),
			env_->LValue(end_of_data));

	out_h->println("void %s;", proto.c_str());

	out_cc->println("void %s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	out_cc->println("try");
	out_cc->inc_indent();
	out_cc->println("{");

	env_->SetEvaluated(begin_of_data);
	env_->SetEvaluated(end_of_data);

	switch ( dataunit_->type() )
		{
		case AnalyzerDataUnit::DATAGRAM:
			GenCodeDatagram(out_cc);
			break;
		case AnalyzerDataUnit::FLOWUNIT:
			GenCodeFlowUnit(out_cc);
			break;
		default:
			ASSERT(0);
		}

	out_cc->println("}");
	out_cc->dec_indent();

	out_cc->println("catch ( binpac::Exception const &e )");
	out_cc->inc_indent();
	out_cc->println("{");
	GenCleanUpCode(out_cc);
	if ( dataunit_->type() == AnalyzerDataUnit::FLOWUNIT )
		{
		out_cc->println("%s->DiscardData();",
			env_->LValue(flow_buffer_id));
		}
	out_cc->println("throw;");
	out_cc->println("}");
	out_cc->dec_indent();

	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("");
	}

void FlowDecl::GenNewDataUnit(Output *out_cc)
	{
	Type *unit_datatype = dataunit_->data_type();
	// dataunit_->data_type()->GenPreParsing(out_cc, env_);
	dataunit_->GenNewDataUnit(out_cc, env_);
	if ( unit_datatype->buffer_input() &&
	     unit_datatype->buffer_mode() == Type::BUFFER_BY_LENGTH )
		{
		out_cc->println("%s->NewFrame(0, false);", 
			env_->LValue(flow_buffer_id));
		}
	dataunit_->GenNewContext(out_cc, env_);
	}

void FlowDecl::GenDeleteDataUnit(Output *out_cc)
	{
	// Do not just delete dataunit, because we may just want to Unref it.
	// out_cc->println("delete %s;", env_->LValue(dataunit_id));
	dataunit_->data_type()->GenCleanUpCode(out_cc, env_);
	dataunit_->context_type()->GenCleanUpCode(out_cc, env_);
	}

void FlowDecl::GenCodeFlowUnit(Output *out_cc)
	{
	Type *unit_datatype = dataunit_->data_type();

	out_cc->println("%s->NewData(%s, %s);",
		env_->LValue(flow_buffer_id),
		env_->RValue(begin_of_data), 
		env_->RValue(end_of_data)); 

	out_cc->println("while ( %s->data_available() && ",
		env_->LValue(flow_buffer_id));
	out_cc->inc_indent();
	out_cc->println("( !%s->have_pending_request() || %s->ready() ) )",
		env_->LValue(flow_buffer_id), env_->LValue(flow_buffer_id));
	out_cc->println("{");

	// Generate a new dataunit if necessary
	out_cc->println("if ( ! %s )", env_->LValue(dataunit_id));
	out_cc->inc_indent();
	out_cc->println("{");
	out_cc->println("BINPAC_ASSERT(!%s);", 
		env_->LValue(analyzer_context_id));
	GenNewDataUnit(out_cc);
	out_cc->println("}");
	out_cc->dec_indent();

	DataPtr data(env_, 0, 0);
	unit_datatype->GenParseCode(out_cc, env_, data, 0);

	out_cc->println("if ( %s )", 
		unit_datatype->parsing_complete(env_).c_str());
	out_cc->inc_indent();
	out_cc->println("{");
	out_cc->println("// Clean up the flow unit after parsing");
	GenDeleteDataUnit(out_cc);
	// out_cc->println("BINPAC_ASSERT(%s == 0);", env_->LValue(dataunit_id));
	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("else");
	out_cc->inc_indent();
	out_cc->println("{");
	out_cc->println("// Resume upon next input segment");
	out_cc->println("BINPAC_ASSERT(!%s->ready());",
		env_->RValue(flow_buffer_id));
	out_cc->println("break;");
	out_cc->println("}");
	out_cc->dec_indent();

	out_cc->println("}");
	out_cc->dec_indent();
	}

void FlowDecl::GenCodeDatagram(Output *out_cc)
	{
	Type *unit_datatype = dataunit_->data_type();
	GenNewDataUnit(out_cc);

	string parse_params = strfmt("%s, %s", 
		env_->RValue(begin_of_data), 
		env_->RValue(end_of_data)); 

	if ( RequiresAnalyzerContext::compute(unit_datatype) )
		{
		parse_params += ", ";
		parse_params += env_->RValue(analyzer_context_id);
		}

	DataPtr dataptr(env_, begin_of_data, 0);
	unit_datatype->GenParseCode(out_cc, env_, dataptr, 0);

	GenDeleteDataUnit(out_cc);
	}
