#ifndef pac_conn_h
#define pac_conn_h

#include "pac_decl.h"
#include "pac_analyzer.h"

class ConnDecl : public AnalyzerDecl
{
public:
	ConnDecl(ID *conn_id, ParamList *params, AnalyzerElementList *elemlist);
	~ConnDecl();

	void Prepare();

	Type* DataType() const	{ return data_type_; }

protected:
	void AddBaseClass(vector<string> *base_classes) const;

	void GenProcessFunc(Output *out_h, Output *out_cc);
	void GenGapFunc(Output *out_h, Output *out_cc);
	void GenEOFFunc(Output *out_h, Output *out_cc);

	void GenPubDecls(Output *out_h, Output *out_cc);
	void GenPrivDecls(Output *out_h, Output *out_cc);

	void ProcessFlowElement(AnalyzerFlow *flow_elem);
	void ProcessDataUnitElement(AnalyzerDataUnit *dataunit_elem);

	AnalyzerFlow *flows_[2];
	Type *data_type_;
};

#endif  // pac_conn_h
