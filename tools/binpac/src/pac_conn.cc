#include "pac_analyzer.h"
#include "pac_dataunit.h"
#include "pac_embedded.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_flow.h"
#include "pac_output.h"
#include "pac_paramtype.h"
#include "pac_type.h"

#include "pac_conn.h"

ConnDecl::ConnDecl(ID *conn_id, 
                   ParamList *params,
                   AnalyzerElementList *elemlist)
	: AnalyzerDecl(conn_id, CONN, params)
	{
	flows_[0] = flows_[1] = 0;
	AddElements(elemlist);
	data_type_ = new ParameterizedType(conn_id->clone(), 0);
	}

ConnDecl::~ConnDecl()
	{
	delete flows_[0];
	delete flows_[1];
	}

void ConnDecl::AddBaseClass(vector<string> *base_classes) const
	{
	base_classes->push_back("binpac::ConnectionAnalyzer"); 
	} 

void ConnDecl::ProcessFlowElement(AnalyzerFlow *flow_elem)
	{
	int flow_index;

	if ( flow_elem->dir() == AnalyzerFlow::UP )
		flow_index = 0;
	else
		flow_index = 1;

	if ( flows_[flow_index] )
		{
		throw Exception(flow_elem,
		                fmt("%sflow already defined", 
		                    flow_index == 0 ? "up" : "down"));
		}

	flows_[flow_index] = flow_elem;
	type_->AddField(flow_elem->flow_field());
	}

void ConnDecl::ProcessDataUnitElement(AnalyzerDataUnit *dataunit_elem)
	{
	throw Exception(
		dataunit_elem, 
		"dataunit should be defined in only a flow declaration");
	}

void ConnDecl::Prepare()
	{
	AnalyzerDecl::Prepare();

	flows_[0]->flow_decl()->set_conn_decl(this);
	flows_[1]->flow_decl()->set_conn_decl(this);
	}

void ConnDecl::GenPubDecls(Output *out_h, Output *out_cc)
	{
	AnalyzerDecl::GenPubDecls(out_h, out_cc);
	}

void ConnDecl::GenPrivDecls(Output *out_h, Output *out_cc)
	{
	AnalyzerDecl::GenPrivDecls(out_h, out_cc);
	}

void ConnDecl::GenEOFFunc(Output *out_h, Output *out_cc)
	{
	string proto = strfmt("%s(bool is_orig)", kFlowEOF);

	out_h->println("void %s;", proto.c_str());

	out_cc->println("void %s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	out_cc->println("if ( is_orig )");
	out_cc->inc_indent();
	out_cc->println("%s->%s();",
	                env_->LValue(upflow_id),
	                kFlowEOF);
	out_cc->dec_indent();
	out_cc->println("else");
	out_cc->inc_indent();
	out_cc->println("%s->%s();",
	                env_->LValue(downflow_id),
	                kFlowEOF);

	foreach(i, AnalyzerHelperList, eof_helpers_)
		{
		(*i)->GenCode(0, out_cc, this);
		}

	out_cc->dec_indent();
	
	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("");
	}

void ConnDecl::GenGapFunc(Output *out_h, Output *out_cc)
	{
	string proto = strfmt("%s(bool is_orig, int gap_length)", kFlowGap);

	out_h->println("void %s;", proto.c_str());

	out_cc->println("void %s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	out_cc->println("if ( is_orig )");
	out_cc->inc_indent();
	out_cc->println("%s->%s(gap_length);",
	                env_->LValue(upflow_id),
	                kFlowGap);
	out_cc->dec_indent();
	out_cc->println("else");
	out_cc->inc_indent();
	out_cc->println("%s->%s(gap_length);",
	                env_->LValue(downflow_id),
	                kFlowGap);
	out_cc->dec_indent();
	
	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("");
	}

void ConnDecl::GenProcessFunc(Output *out_h, Output *out_cc)
	{
	string proto = 
		strfmt("%s(bool is_orig, const_byteptr begin, const_byteptr end)",
		       kNewData);

	out_h->println("void %s;", proto.c_str());

	out_cc->println("void %s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	out_cc->println("if ( is_orig )");
	out_cc->inc_indent();
	out_cc->println("%s->%s(begin, end);",
	                env_->LValue(upflow_id),
	                kNewData);
	out_cc->dec_indent();
	out_cc->println("else");
	out_cc->inc_indent();
	out_cc->println("%s->%s(begin, end);",
	                env_->LValue(downflow_id),
	                kNewData);
	out_cc->dec_indent();
	
	out_cc->println("}");
	out_cc->dec_indent();
	out_cc->println("");
	}
