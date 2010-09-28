#ifndef pac_flow_h
#define pac_flow_h

#include "pac_analyzer.h"

class FlowDecl : public AnalyzerDecl
{
public:
	FlowDecl(ID *flow_id, ParamList *params, AnalyzerElementList *elemlist);
	~FlowDecl();

	void Prepare();

	void set_conn_decl(ConnDecl *c)	{ conn_decl_ = c; }

	static ParameterizedType *flow_buffer_type();

protected:
	void AddBaseClass(vector<string> *base_classes) const;

	void GenInitCode(Output *out_cc);
	void GenCleanUpCode(Output *out_cc);
	void GenProcessFunc(Output *out_h, Output *out_cc);
	void GenEOFFunc(Output *out_h, Output *out_cc);
	void GenGapFunc(Output *out_h, Output *out_cc);

	void GenPubDecls(Output *out_h, Output *out_cc);
	void GenPrivDecls(Output *out_h, Output *out_cc);

	void ProcessFlowElement(AnalyzerFlow *flow_elem);
	void ProcessDataUnitElement(AnalyzerDataUnit *dataunit_elem);

private:
	void GenNewDataUnit(Output *out_cc);
	void GenDeleteDataUnit(Output *out_cc);
	void GenCodeFlowUnit(Output *out_cc);
	void GenCodeDatagram(Output *out_cc);

	AnalyzerDataUnit *dataunit_;
	ConnDecl *conn_decl_;

	Field *flow_buffer_var_field_;

	static ParameterizedType *flow_buffer_type_;
};

#endif  // pac_flow_h
