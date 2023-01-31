#ifndef pac_conn_h
#define pac_conn_h

#include "pac_analyzer.h"
#include "pac_decl.h"

class ConnDecl : public AnalyzerDecl
	{
public:
	ConnDecl(ID* conn_id, ParamList* params, AnalyzerElementList* elemlist);
	~ConnDecl() override;

	void Prepare() override;

	Type* DataType() const { return data_type_; }

protected:
	void AddBaseClass(vector<string>* base_classes) const override;

	void GenProcessFunc(Output* out_h, Output* out_cc) override;
	void GenGapFunc(Output* out_h, Output* out_cc) override;
	void GenEOFFunc(Output* out_h, Output* out_cc) override;

	void GenPubDecls(Output* out_h, Output* out_cc) override;
	void GenPrivDecls(Output* out_h, Output* out_cc) override;

	void ProcessFlowElement(AnalyzerFlow* flow_elem) override;
	void ProcessDataUnitElement(AnalyzerDataUnit* dataunit_elem) override;

	AnalyzerFlow* flows_[2];
	Type* data_type_;
	};

#endif // pac_conn_h
