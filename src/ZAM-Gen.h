// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <assert.h>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <unordered_set>
#include <unordered_map>

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

class ZAMGen;

// We only use the following in the context where the vector's elements
// are individual words from the same line.  We don't use it in other
// contexts where we're tracking a bunch of strings.
using Words = vector<string>;

struct InputLoc {
	const char* file_name;
	int line_num = 0;
};

enum EmitTarget {
	None,
	BaseDecl,
	SubDecl,
	MethodDef,
	DirectDef,
	C1Def,
	C2Def,
	C3Def,
	VDef,
	Cond,
	Eval,
	AssignFlavor,
	Op1Flavor,
	OpSideEffects,
	OpDef,
	OpName,
};

// Helper class.
class ArgsManager {
public:
	ArgsManager(const vector<ZAM_OperandType>& ot, bool is_cond);

	string Decls()			{ return full_decl; }
	string Params()			{ return full_params; }
	const string& NthParam(int n)	{ return params[n]; }

private:
	void Differentiate();

	static std::unordered_map<ZAM_OperandType,
	        std::pair<const char*, const char*>> ot_to_args;

	struct Arg {
		string decl_name;
		string decl_type;
		string param_name;
		bool is_field;
	};

	vector<Arg> args;

	vector<string> params;
	string full_decl;
	string full_params;
};

class ZAM_OpTemplate {
public:
	ZAM_OpTemplate(ZAMGen* _g, string _base_name);
	virtual ~ZAM_OpTemplate()	{ }

	void Build();
	virtual void Instantiate();

	const string& BaseName() const	{ return base_name; }
	const string& OrigName() const	{ return orig_name; }
	const string& CanonicalName() const	{ return cname; }

	void AddOpType(ZAM_OperandType ot)
		{ op_types.push_back(ot); }
	const vector<ZAM_OperandType>& OperandTypes() const
		{ return op_types; }

	void SetOp1Flavor(string fl)		{ op1_flavor = fl; }
	const string& GetOp1Flavor() const	{ return op1_flavor; }

	void SetTypeParam(int param)		{ type_param = param; }
	int GetTypeParam() const		{ return type_param; }

	void SetType2Param(int param)		{ type2_param = param; }
	int GetType2Param() const		{ return type2_param; }

	void SetAssignVal(string _av)		{ av = _av; }
	bool HasAssignVal() const		{ return av.size() > 0; }
	const string& GetAssignVal() const	{ return av; }

	void AddEval(string line)		{ evals.push_back(line); }
	bool HasEvals() const			{ return evals.size() > 0; }
	const vector<string>& Evals() const	{ return evals; }
	string CompleteEval() const;

	void SetCustomMethod(string cm)		{ custom_method = SkipWS(cm); }
	bool HasCustomMethod() const
		{ return custom_method.size() > 0; }
	const string& GetCustomMethod() const
		{ return custom_method; }

	void SetPostMethod(string cm)		{ post_method = SkipWS(cm); }
	bool HasPostMethod() const
		{ return post_method.size() > 0; }
	const string& GetPostMethod() const
		{ return post_method; }

	virtual bool IncludesFieldOp() const		{ return false; }
	virtual bool IncludesConditional() const	{ return false; }
	virtual bool IsInternalOp() const		{ return false; }
	virtual bool IsAssignOp() const			{ return false; }
	virtual bool IsFieldOp() const			{ return false; }

	bool NoEval() const	{ return no_eval; }
	void SetNoEval() 	{ no_eval = true; }

	bool NoConst() const			{ return no_const; }
	void SetNoConst()			{ no_const = true; }

	bool IncludesVectorOp() const	{ return includes_vector_op; }
	void SetIncludesVectorOp() 	{ includes_vector_op = true; }

	bool HasSideEffects() const	{ return has_side_effects; }
	void SetHasSideEffects()	{ has_side_effects = true; }

	bool HasAssignmentLess() const
		{ return assignment_less_op.size() > 0; }
	void SetAssignmentLess(string op, string op_type)
		{
		assignment_less_op = op;
		assignment_less_op_type = op_type;
		}
	const string& AssignmentLessOp() const
		{ return assignment_less_op; }
	const string& AssignmentLessOpType() const
		{ return assignment_less_op_type; }

protected:
	virtual void Parse(const string& attr, const string& line, const Words& words);
	string GatherEvals();
	int ExtractTypeParam(const string& arg);

	void UnaryInstantiate();
	void InstantiateOp(const vector<ZAM_OperandType>& ot, bool do_vec);
	void InstantiateOp(const string& m,
	                   const vector<ZAM_OperandType>& ot,
	                   bool is_field, bool is_vec, bool is_cond);
	void InstantiateMethod(const string& m, const string& suffix,
	                       const vector<ZAM_OperandType>& ot,
	                       bool is_field, bool is_vec, bool is_cond);
	void InstantiateMethodCore(const vector<ZAM_OperandType>& ot,
				   string suffix,
	                           bool is_field, bool is_vec, bool is_cond);
	virtual void BuildInstruction(const string& op,
	                              const string& suffix,
			              const vector<ZAM_OperandType>& ot,
	                              const string& params);
	virtual void InstantiateEval(const vector<ZAM_OperandType>& ot,
	                             const string& suffix,
	                             bool is_field, bool is_vec, bool is_cond);
	void InstantiateAssignOp(const vector<ZAM_OperandType>& ot,
	                         const string& suffix);
	void GenAssignOpCore(const vector<ZAM_OperandType>& ot,
	                     const string& eval, const string& accessor,
			     bool is_managed);

	string MethodName(const vector<ZAM_OperandType>& ot) const;
	string MethodDecl(const vector<ZAM_OperandType>& ot,
	                  bool is_field, bool is_cond);
	string OpString(const vector<ZAM_OperandType>& ot) const;

	string SkipWS(const string& s) const;

	void Emit(const string& s);
	void EmitTo(EmitTarget et)	{ curr_et = et; }
	void EmitUp(const string& s)
		{
		IndentUp();
		Emit(s);
		IndentDown();
		}
	void EmitNoNL(const string& s);

	void NL()	{ Emit(""); }

	void IndentUp();
	void IndentDown();
	void BeginBlock()	{ IndentUp(); Emit("{"); }
	void EndBlock()		{ Emit("}"); IndentDown(); }

	static std::unordered_map<ZAM_OperandType, char> ot_to_char;

	ZAMGen* g;

	string base_name;
	string orig_name;
	string cname;

	InputLoc op_loc;

	EmitTarget curr_et = None;

	vector<ZAM_OperandType> op_types;
	string op1_flavor = "OP1_WRITE";

	int type_param = 0;	// 0 = not set
	int type2_param = 0;

	// If non-empty, the value to assign to the target in an assignment
	// operation.
	string av;

	vector<string> evals;

	string custom_method;
	string post_method;

	bool no_eval = false;
	bool no_const = false;
	bool includes_vector_op = false;
	bool has_side_effects = false;

	string assignment_less_op;
	string assignment_less_op_type;
};

class ZAM_UnaryOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_UnaryOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_OpTemplate(_g, _base_name) { }

protected:
	void Instantiate() override;
};

class ZAM_DirectUnaryOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_DirectUnaryOpTemplate(ZAMGen* _g, string _base_name, string _direct)
	: ZAM_OpTemplate(_g, _base_name), direct(_direct) { }

protected:
	void Instantiate() override;

private:
	string direct;
};

class ZAM_ExprOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_ExprOpTemplate(ZAMGen* _g, string _base_name);

	virtual int Arity() const			{ return 0; }

	int TypeSelector() const	{ return type_selector; }
	void SetTypeSelector(int ts)	{ type_selector = ts; }

	void AddExprType(ZAM_ExprType et)
		{ expr_types.insert(et); }
	const std::unordered_set<ZAM_ExprType>& ExprTypes()
		{ return expr_types; }

	void AddEvalSet(ZAM_ExprType et, string ev)
		{ eval_set[et].emplace_back(ev); }
	void AddEvalSet(ZAM_ExprType et1, ZAM_ExprType et2, string ev)
		{ eval_mixed_set[et1][et2].emplace_back(ev); }

	bool IncludesFieldOp() const override	{ return includes_field_op; }
	void SetIncludesFieldOp()		{ includes_field_op = true; }

	bool HasPreEval() const			{ return pre_eval.size() > 0; }
	void SetPreEval(string pe)		{ pre_eval = SkipWS(pe); }
	const string& GetPreEval() const	{ return pre_eval; }

protected:
	void Parse(const string& attr, const string& line, const Words& words) override;
	void Instantiate() override;

	void InstantiateC1(const vector<ZAM_OperandType>& ots, int arity,
	                   bool do_vec = false);
	void InstantiateC2(const vector<ZAM_OperandType>& ots, int arity);
	void InstantiateC3(const vector<ZAM_OperandType>& ots);

	void InstantiateV(const vector<ZAM_OperandType>& ots);

	void DoVectorCase(const string& m, const string& args);

private:
	std::unordered_set<ZAM_ExprType> expr_types;

	std::unordered_map<ZAM_ExprType, vector<string>> eval_set;
	std::unordered_map<ZAM_ExprType,
	 std::unordered_map<ZAM_ExprType, vector<string>>>
	  eval_mixed_set;

	bool includes_field_op = false;

	// If non-zero, code to generate prior to evaluating the expression.
	string pre_eval;

	// If non-zero, specifies which operand to use to determine
	// the result type of the expression.
	int type_selector = 0;
};

class ZAM_UnaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
	ZAM_UnaryExprOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_ExprOpTemplate(_g, _base_name) { }

	bool IncludesFieldOp() const override	{ return true; }

	int Arity() const override		{ return 1; }

protected:
	virtual void Parse(const string& attr, const string& line, const Words& words) override;
	void Instantiate() override;

	void BuildInstruction(const string& op,
	                      const string& suffix,
			      const vector<ZAM_OperandType>& ot,
	                      const string& params) override;
};

class ZAM_AssignOpTemplate : public ZAM_UnaryExprOpTemplate {
public:
	ZAM_AssignOpTemplate(ZAMGen* _g, string _base_name);

	bool IsAssignOp() const override	{ return true; }
	bool IncludesFieldOp() const override	{ return false; }
	bool IsFieldOp() const override		{ return field_op; }
	void SetFieldOp()			{ field_op = true; }

protected:
	void Parse(const string& attr, const string& line, const Words& words) override;
	void Instantiate() override;

private:
	bool field_op = false;
};

class ZAM_BinaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
	ZAM_BinaryExprOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_ExprOpTemplate(_g, _base_name) { }

	bool IncludesFieldOp() const override	{ return true; }

	int Arity() const override		{ return 2; }

protected:
	void Instantiate() override;
};

class ZAM_RelationalExprOpTemplate : public ZAM_BinaryExprOpTemplate {
public:
	ZAM_RelationalExprOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_BinaryExprOpTemplate(_g, _base_name) { }

	bool IncludesFieldOp() const override		{ return false; }
	bool IncludesConditional() const override	{ return true; }

protected:
	void Instantiate() override;
};

class ZAM_InternalBinaryOpTemplate : public ZAM_BinaryExprOpTemplate {
public:
	ZAM_InternalBinaryOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_BinaryExprOpTemplate(_g, _base_name) { }

	bool IsInternalOp() const override	{ return true; }

	void SetOp1Accessor(string accessor)	{ op1_accessor = accessor; }
	void SetOp2Accessor(string accessor)	{ op2_accessor = accessor; }
	void SetOpAccessor(string accessor)
		{
		SetOp1Accessor(accessor); 
		SetOp2Accessor(accessor);
		}

protected:
	virtual void Parse(const string& attr, const string& line, const Words& words) override;

private:
	string op1_accessor;
	string op2_accessor;
};

class ZAM_InternalOpTemplate : public ZAM_OpTemplate {
public:
	ZAM_InternalOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_OpTemplate(_g, _base_name) { }

	bool IsInternalOp() const override	{ return true; }
};

class ZAM_InternalAssignOpTemplate : public ZAM_InternalOpTemplate {
public:
	ZAM_InternalAssignOpTemplate(ZAMGen* _g, string _base_name)
	: ZAM_InternalOpTemplate(_g, _base_name) { }

	bool IsAssignOp() const override	{ return true; }
};


// Helper classes for managing input from the template file, including
// low-level scanning.

class TemplateInput {
public:
	TemplateInput(FILE* _f, const char* _prog_name, const char* _file_name)
	: f(_f), prog_name(_prog_name)
		{
		loc.file_name = _file_name;
		}

	const InputLoc& CurrLoc() const	{ return loc; }

	bool ScanLine(string& line);
	Words SplitIntoWords(const string& line) const;
	string AllButFirstWord(const string& line) const;
	void PutBack(const string& line)	{ put_back = line; }

	void Gripe(const char* msg, const string& input);
	void Gripe(const char* msg, const InputLoc& loc);

private:
	string put_back;	// if non-empty, use this for the next ScanLine

	FILE* f;
	const char* prog_name;
	InputLoc loc;
};


class ZAMGen {
public:
	ZAMGen(int argc, char** argv);

	const InputLoc& CurrLoc() const	{ return ti->CurrLoc(); }
	bool ScanLine(string& line)	{ return ti->ScanLine(line); }
	Words SplitIntoWords(const string& line) const
		{ return ti->SplitIntoWords(line); }
	string AllButFirstWord(const string& line) const
		{ return ti->AllButFirstWord(line); }
	void PutBack(const string& line)	{ ti->PutBack(line); }

	string GenOpCode(const ZAM_OpTemplate* ot, const string& suffix);

	void Emit(EmitTarget et, const string& s);
	void IndentUp()			{ ++indent_level; }
	void IndentDown()		{ --indent_level; }
	void SetNoNL(bool _no_NL)	{ no_NL = _no_NL; }

	void Gripe(const char* msg, const string& input)
		{ ti->Gripe(msg, input); }
	void Gripe(const char* msg, const InputLoc& loc)
		{ ti->Gripe(msg, loc); }

private:
	bool ParseTemplate();

	std::unique_ptr<TemplateInput> ti;
	vector<std::unique_ptr<ZAM_OpTemplate>> templates;

	int indent_level = 0;
	bool no_NL = false;
};
