#ifndef pac_analyzer_h
#define pac_analyzer_h

#include "pac_common.h"
#include "pac_field.h"
#include "pac_typedecl.h"

class AnalyzerElement;
class AnalyzerState;
class AnalyzerAction;	// defined in pac_action.h
class AnalyzerHelper;
class AnalyzerFlow;
class AnalyzerDataUnit;
class AnalyzerFunction;
class ConnDecl;
class FlowDecl;
typedef vector<AnalyzerHelper *> AnalyzerHelperList;
typedef vector<Function *> FunctionList;

class AnalyzerDecl : public TypeDecl
{
public:
	AnalyzerDecl(ID *id, DeclType decl_type, ParamList *params);
	~AnalyzerDecl();

	void AddElements(AnalyzerElementList *elemlist);

	void Prepare();
	void GenForwardDeclaration(Output *out_h);
	// void GenCode(Output *out_h, Output *out_cc);

	void GenInitCode(Output *out_cc);
	void GenCleanUpCode(Output *out_cc);

	string class_name() const;
	// string cookie_name() const;

protected:
	virtual void ProcessFlowElement(AnalyzerFlow *flow_elem) = 0;
	virtual void ProcessDataUnitElement(AnalyzerDataUnit *dataunit_elem) = 0;

	// Generate public/private declarations for member functions and 
	// variables
	void GenPubDecls(Output *out_h, Output *out_cc);
	void GenPrivDecls(Output *out_h, Output *out_cc);

	// Generate the NewData() function
	virtual void GenProcessFunc(Output *out_h, Output *out_cc) = 0;

	// Generate the NewGap() function
	virtual void GenGapFunc(Output *out_h, Output *out_cc) = 0;

	// Generate the FlowEOF() function
	virtual void GenEOFFunc(Output *out_h, Output *out_cc) = 0;

	// Generate the functions
	void GenFunctions(Output *out_h, Output *out_cc);

	// Generate the action functions
	void GenActions(Output *out_h, Output *out_cc);

	// Generate the helper code segments
	void GenHelpers(Output *out_h, Output *out_cc);

	// Generate declarations for state variables and their set functions
	void GenStateVarDecls(Output *out_h);
	void GenStateVarSetFunctions(Output *out_h);

	// Generate code for initializing and cleaning up (including
	// memory de-allocating) state variables
	void GenStateVarInitCode(Output *out_cc);
	void GenStateVarCleanUpCode(Output *out_cc);

	StateVarList *statevars_;
	AnalyzerActionList *actions_;
	AnalyzerHelperList *helpers_;
	FunctionList *functions_;

	AnalyzerHelperList *constructor_helpers_;
	AnalyzerHelperList *destructor_helpers_;
	AnalyzerHelperList *eof_helpers_;
};

class AnalyzerElement : public Object
{
public:
	enum ElementType { STATE, ACTION, FUNCTION, HELPER, FLOW, DATAUNIT };
	AnalyzerElement(ElementType type)
		: type_(type) {}
	virtual ~AnalyzerElement() {}

	ElementType type() const	{ return type_; }

private:
	ElementType type_;
};

// A collection of variables representing analyzer states.
class AnalyzerState : public AnalyzerElement
{
public:
	AnalyzerState(StateVarList *statevars)
		: AnalyzerElement(STATE),
		  statevars_(statevars) {}
	~AnalyzerState();

	StateVarList *statevars() const	{ return statevars_; }

private:
	StateVarList *statevars_;
};

// A collection of embedded C++ code
class AnalyzerHelper : public AnalyzerElement
{
public:
	enum Type {
		MEMBER_DECLS,
		INIT_CODE,
		CLEANUP_CODE,
		EOF_CODE,
	};
	AnalyzerHelper(Type helper_type, EmbeddedCode *code)
		: AnalyzerElement(HELPER),
		  helper_type_(helper_type), 
		  code_(code) {}
	~AnalyzerHelper();

	Type helper_type() const	{ return helper_type_; }

	void GenCode(Output *out_h, Output *out_cc, AnalyzerDecl *decl);

	EmbeddedCode *code() const	{ return code_; }

private:
	Type helper_type_;
	EmbeddedCode *code_;
};

// The type and parameters of (uni-directional) flows of a connection.

class FlowField : public Field
{
public:
	FlowField(ID *flow_id, ParameterizedType *flow_type);
	void GenInitCode(Output *out, Env *env);
};

class AnalyzerFlow : public AnalyzerElement
{
public:
	enum Direction { UP, DOWN };
	AnalyzerFlow(Direction dir, ID *type_id, ExprList *params);
	~AnalyzerFlow();

	Direction dir() const		{ return dir_; }
	FlowField *flow_field() const	{ return flow_field_; }

	FlowDecl *flow_decl();

private:
	Direction dir_;
	ID *type_id_;
	FlowField *flow_field_;
	FlowDecl *flow_decl_;
};

#endif  // pac_analyzer_h
