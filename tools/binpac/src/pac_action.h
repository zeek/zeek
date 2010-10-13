#ifndef pac_action_h
#define pac_action_h

// Classes representing analyzer actions.

#include "pac_common.h"
#include "pac_analyzer.h"

class AnalyzerAction : public AnalyzerElement
{
public:
	enum When { BEFORE, AFTER };

	AnalyzerAction(ID *action_id, 
	               When when, 
	               ActionParam *param, 
	               EmbeddedCode *code);

	~AnalyzerAction();

	When when() const		{ return when_; }
	ActionParam *param() const	{ return param_; }
	AnalyzerDecl *analyzer() const	{ return analyzer_; }
	string action_function() const;

	// Generate function prototype and code for the action
	void GenCode(Output *out_h, Output *out_cc, AnalyzerDecl *decl);

	// Install the hook at the corresponding data type parsing
	// function to invoke the action.
	void InstallHook(AnalyzerDecl *analyzer);

private:
	string ParamDecls(Env *env) const;

	ID *action_id_;
	When when_;
	ActionParam *param_;
	EmbeddedCode *code_;
	AnalyzerDecl *analyzer_;
};

class ActionParam
{
public:
	ActionParam(const ID *id, ActionParamType *type)
		: id_(id), type_(type) {}

	const ID *id() const		{ return id_; }
	ActionParamType *type() const	{ return type_; }

	Type *MainDataType() const;
	Type *DataType() const;
	string DeclStr(Env *env) const;

private:
	const ID *id_;
	ActionParamType *type_;
};

class ActionParamType
{
public:
	ActionParamType(const ID *type_id, const ID *field_id = 0)
		: type_id_(type_id), field_id_(field_id) {}

	const ID *type_id() const	{ return type_id_; }
	const ID *field_id() const	{ return field_id_; }

protected:
	const ID *type_id_, *field_id_;
};

#endif  // pac_action_h
