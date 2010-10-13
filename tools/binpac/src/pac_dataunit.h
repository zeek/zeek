#ifndef pac_dataunit_h
#define pac_dataunit_h

#include "pac_analyzer.h"

// The type and parameters of input data unit of a flow. For instance, the
// data unit of a DCE/RPC flow is DCE_RPC_PDU.

class AnalyzerDataUnit : public AnalyzerElement
{
public:
	enum DataUnitType { DATAGRAM, FLOWUNIT };
	AnalyzerDataUnit(
		DataUnitType type, 
		ID *id, 
		ExprList *type_params, 
		ExprList *context_params);
	~AnalyzerDataUnit();

	void Prepare(Env *env);

	// Initializes dataunit_id
	void GenNewDataUnit(Output *out_cc, Env *env);
	// Initializes analyzer_context_id
	void GenNewContext(Output *out_cc, Env *env);

	DataUnitType type() const		{ return type_; }
	const ID *id() const			{ return id_; }
	ExprList *type_params() const		{ return type_params_; }
	ExprList *context_params() const	{ return context_params_; }

	ParameterizedType *data_type() const	{ return data_type_; }
	ParameterizedType *context_type() const	{ return context_type_; }

	Field *dataunit_var_field() const	{ return dataunit_var_field_; }
	Field *context_var_field() const	{ return context_var_field_; }

private:
	DataUnitType type_;
	ID *id_;
	ExprList *type_params_;
	ExprList *context_params_;
	ParameterizedType *data_type_;
	ParameterizedType *context_type_;
	Field *dataunit_var_field_;
	Field *context_var_field_;
};

#endif // pac_dataunit_h
