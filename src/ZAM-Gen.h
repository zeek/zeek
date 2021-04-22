// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <ZInst.h>

using std::string;
using std::vector;

enum ZAM_OperandType {
	ZAM_OT_AUX,
	ZAM_OT_CONSTANT,
	ZAM_OT_EVENT_HANDLER,
	ZAM_OT_FIELD,
	ZAM_OT_INT,
	ZAM_OT_LIST,
	ZAM_OT_RECORD_FIELD,
	ZAM_OT_VAR,	// a frame slot

	ZAM_OT_NONE
};

enum ZAM_ExprType {
	ZAM_EXPR_TYPE_ADDR,
	ZAM_EXPR_TYPE_DOUBLE,
	ZAM_EXPR_TYPE_DOUBLE_CUSTOM,
	ZAM_EXPR_TYPE_INT,
	ZAM_EXPR_TYPE_INT_CUSTOM,
	ZAM_EXPR_TYPE_PORT,
	ZAM_EXPR_TYPE_STRING,
	ZAM_EXPR_TYPE_SUBNET,
	ZAM_EXPR_TYPE_TABLE,
	ZAM_EXPR_TYPE_UINT,
	ZAM_EXPR_TYPE_UINT_CUSTOM,
	ZAM_EXPR_TYPE_VECTOR,

	ZAM_EXPR_TYPE_ANY,
	ZAM_EXPR_TYPE_NONE,
};

class TemplateInput;

// We only use the following in the context where the vector's elements
// are individual words from the same line.  We don't use it in other
// contexts where we're tracking a bunch of strings.
using Words = vector<string>;

class ZAM_OpTemplate {
public:
	ZAM_OpTemplate(TemplateInput* _ti, string _base_name);
	virtual ~ZAM_OpTemplate()	{ }

	void Build();

	void AddOpType(ZAM_OperandType ot)
		{ ots.push_back(ot); }
	const vector<ZAM_OperandType>& OperandTypes() const
		{ return ots; }

	void SetOp1Flavor(ZAMOp1Flavor fl)	{ op1_flavor = fl; }
	ZAMOp1Flavor GetOp1Flavor() const	{ return op1_flavor; }

	void SetTypeParam(int param)		{ type_param = param; }
	int GetTypeParam() const		{ return type_param; }

	void SetType2Param(int param)		{ type2_param = param; }
	int GetType2Param() const		{ return type2_param; }

	void AddEval(string line)		{ evals.push_back(line); }
	bool HasEvals() const			{ return evals.size() > 0; }
	const vector<string>& Evals() const	{ return evals; }

	void SetCustomMethod(string cm)		{ custom_method = cm; }
	bool HasCustomMethod() const
		{ return custom_method.size() > 0; }
	const string& GetCustomMethod() const
		{ return custom_method; }

	void SetPostMethod(string cm)		{ post_method = cm; }
	bool HasPostMethod() const
		{ return post_method.size() > 0; }
	const string& GetPostMethod() const
		{ return post_method; }

	virtual bool IncludesFieldOp() const		{ return false; }
	virtual bool IsInternal() const			{ return false; }

	bool IncludesVectorOp() const	{ return includes_vector_op; }
	void SetIncludesVectorOp() 	{ includes_vector_op = true; }

	bool HasSideEffects() const	{ return has_side_effects; }
	void SetHasSideEffects()	{ has_side_effects = true; }

	bool HasSpecificSideEffects() const
		{ return specific_side_effects.size() > 0; }
	void SetSpecificSideEffects(string sse, string sse_ot)
		{
		specific_side_effects = sse;
		specific_side_effects_op_type = sse_ot;
		}
	const string& SpecificSideEffects() const
		{ return specific_side_effects; }
	const string& SpecificSideEffectsOpType() const
		{ return specific_side_effects_op_type; }

protected:
	virtual void Parse(const string& attr, const string& line, const Words& words);
	int ExtractTypeParam(const string& arg);

	TemplateInput* ti;

	string base_name;

	vector<ZAM_OperandType> ots;
	ZAMOp1Flavor op1_flavor;

	int type_param = 0;	// 0 = not set
	int type2_param = 0;

	vector<string> evals;

	string custom_method;
	string post_method;

	bool includes_vector_op = false;
	bool has_side_effects = false;

	string specific_side_effects;
	string specific_side_effects_op_type;
};

class ZAM_UnaryOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_UnaryOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_OpTemplate(_ti, _base_name) { }

	bool HasDirectOp() const		{ return direct_op.size() > 0; }
	void SetDirectOp(string d_o)		{ direct_op = d_o; }
	const string& GetDirectOp() const	{ return direct_op; }

	bool NoConst() const			{ return no_const; }
	void SetNoConst()			{ no_const = true; }

protected:
	virtual void Parse(const string& attr, const string& line, const Words& words);

private:
	string direct_op;
	bool no_const = false;
};

class ZAM_DirectUnaryOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_DirectUnaryOpTemplate(TemplateInput* _ti, string _base_name, string _direct)
	: ZAM_OpTemplate(_ti, _base_name), direct(_direct) { }

private:
	std::string direct;
};

class ZAM_AssignOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_AssignOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_OpTemplate(_ti, _base_name) { }

	bool IncludesFieldOp() const override	{ return field_op; }

private:
	bool field_op = false;
};

class ZAM_ExprOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_ExprOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_OpTemplate(_ti, _base_name) { }

	bool IncludesFieldOp() const override	{ return true; }

	virtual int Arity() const			{ return 0; }

	int TypeSelector() const	{ return type_selector; }
	void SetTypeSelector(int ts)	{ type_selector = ts; }

	void AddExprType(ZAM_ExprType et)
		{ expr_types.insert(et); }

	void AddEvalSet(ZAM_ExprType et, string ev)
		{ eval_set[et].emplace_back(ev); }
	void AddEvalSet(ZAM_ExprType et1, ZAM_ExprType et2, string ev)
		{ eval_mixed_set[et1][et2].emplace_back(ev); }

	bool HasPreEval() const			{ return pre_eval.size() > 0; }
	void SetPreEval(string pe)		{ pre_eval = pe; }
	const string GetPreEval() const	{ return pre_eval; }

protected:
	void Parse(const string& attr, const string& line, const Words& words) override;

private:
	std::unordered_set<ZAM_ExprType> expr_types;

	std::unordered_map<ZAM_ExprType, vector<string>> eval_set;
	std::unordered_map<ZAM_ExprType,
	 std::unordered_map<ZAM_ExprType, vector<string>>>
	  eval_mixed_set;

	// If non-zero, code to generate prior to evaluating the expression.
	string pre_eval;

	// If non-zero, specifies which operand to use to determine
	// the result type of the expression.
	int type_selector = 0;
};

class ZAM_UnaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
	ZAM_UnaryExprOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_ExprOpTemplate(_ti, _base_name) { }

	int Arity() const override		{ return 1; }
};

class ZAM_BinaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
	ZAM_BinaryExprOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_ExprOpTemplate(_ti, _base_name) { }

	int Arity() const override		{ return 2; }
};

class ZAM_RelationalExprOpTemplate : public ZAM_BinaryExprOpTemplate {
public:
	ZAM_RelationalExprOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_BinaryExprOpTemplate(_ti, _base_name) { }
};

class ZAM_InternalBinaryOpTemplate : public ZAM_BinaryExprOpTemplate {
public:
	ZAM_InternalBinaryOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_BinaryExprOpTemplate(_ti, _base_name) { }

	bool IsInternal() const override	{ return true; }

	void SetOp1Accessor(string accessor)	{ op1_accessor = accessor; }
	void SetOp2Accessor(string accessor)	{ op2_accessor = accessor; }
	void SetOpAccessor(string accessor)
		{
		SetOp1Accessor(accessor); 
		SetOp2Accessor(accessor);
		}

private:
	string op1_accessor;
	string op2_accessor;
};

class ZAM_InternalOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_InternalOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_OpTemplate(_ti, _base_name) { }

	bool IsInternal() const override	{ return true; }
};

class ZAM_InternalAssignOpTemplate : public ZAM_InternalOpTemplate {
public:
	ZAM_InternalAssignOpTemplate(TemplateInput* _ti, string _base_name)
	: ZAM_InternalOpTemplate(_ti, _base_name) { }
};


// Helper class for managing input from the template file, including
// low-level scanning.
class TemplateInput {
public:
	TemplateInput(FILE* _f, const char* _prog_name, const char* _file_name)
	: f(_f), prog_name(_prog_name), file_name(_file_name)
		{ }

	bool ScanLine(string& line);
	Words SplitIntoWords(const string& line) const;
	string AllButFirstWord(const string& line) const;
	void PutBack(const string& line)	{ put_back = line; }
	void Gripe(const char* msg, const string& input);

private:
	string put_back;	// if non-empty, use this for the next ScanLine

	FILE* f;
	const char* prog_name;
	const char* file_name;
	int line_num = 0;
};


class ZAMGen {
public:
	ZAMGen(int argc, char** argv);

private:
	bool ParseTemplate();

	std::unique_ptr<TemplateInput> ti;
	vector<std::unique_ptr<ZAM_OpTemplate>> templates;
};
