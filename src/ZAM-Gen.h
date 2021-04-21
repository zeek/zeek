#include <ZInst.h>

enum ZAM_OperandType {
	ZAM_OT_CONSTANT,
	ZAM_OT_VAR,	// a frame slot
	ZAM_OT_INT,
	ZAM_OT_LIST,
	ZAM_OT_EVENT_HANDLER,
	ZAM_OT_AUX,
	ZAM_OT_RECORD_FIELD,
};

enum ZAM_ExprType {
	ZAM_EXPR_TYPE_ADDR,
	ZAM_EXPR_TYPE_DOUBLE,
	ZAM_EXPR_TYPE_DOUBLE_CUSTOM,
	ZAM_EXPR_TYPE_INT,
	ZAM_EXPR_TYPE_INT_CUSTOM,
	ZAM_EXPR_TYPE_NONE,
	ZAM_EXPR_TYPE_PORT,
	ZAM_EXPR_TYPE_SET,
	ZAM_EXPR_TYPE_SUBNET,
	ZAM_EXPR_TYPE_TABLE,
	ZAM_EXPR_TYPE_UINT,
	ZAM_EXPR_TYPE_UINT_CUSTOM,
	ZAM_EXPR_TYPE_VECTOR,

	ZAM_EXPR_TYPE_ALL,
};

class ZAM_OpTemplate {
public:
	ZAM_OpTemplate(std::string _base_name);

	void AddOpType(ZAM_OperandType ot)
		{ ots.push_back(ot); }
	const std::vector<ZAM_OperandType>& OperandTypes() const
		{ return ots; }

	void SetOp1Flavor(ZAMOp1Flavor fl)	{ op1_flavor = fl; }
	ZAMOp1Flavor GetOp1Flavor() const	{ return op1_flavor; }

	void SetTypeParam(int param)		{ type_param = param; }
	int GetTypeParam() const		{ return type_param; }

	void SetType2Param(int param)		{ type2_param = param; }
	int GetType2Param() const		{ return type2_param; }

	void AddEval(std::string line)
		{ evals.push_back(std::move(line)); }
	bool HasEvals() const			{ return evals.size() > 0; }
	const std::vector<std::string>& Evals() const	{ return evals; }

	void SetCustomMethod(std::string cm)
		{ custom_method = std::move(cm); }
	bool HasCustomMethod() const
		{ return custom_method.size() > 0; }
	const std::string& GetCustomMethod() const
		{ return custom_method; }

	void SetPostMethod(std::string cm)
		{ post_method = std::move(cm); }
	bool HasPostMethod() const
		{ return post_method.size() > 0; }
	const std::string& GetPostMethod() const
		{ return post_method; }

	virtual int Arity() const			{ return 0; }
	virtual bool IncludesFieldOp() const		{ return false; }
	virtual bool IsInternal() const			{ return false; }

	bool IncludesVectorOp() const	{ return includes_vector_op; }
	void SetIncludesVectorOp() 	{ includes_vector_op = true; }

	virtual bool HasSideEffects() const		{ return false; }
	bool HasSpecificSideEffects() const
		{ return specific_side_effects.size() > 0; }
	void SetSpecificSideEffects(std::string sse, std::string sse_ot)
		{
		specific_side_effects = std::move(sse);
		specific_side_effects_op_type = std::move(sse_ot);
		}
	const std::string& SpecificSideEffects() const
		{ return specific_side_effects; }
	const std::string& SpecificSideEffectsOpType() const
		{ return specific_side_effects_op_type; }

protected:
	std::string base_name;

	std::vector<ZAM_OperandType> ots;
	ZAMOp1Flavor op1_flavor;

	int type_param = 0;	// 0 = not set
	int type2_param = 0;

	std::vector<std::string> evals;

	std::string custom_method;
	std::string post_method;

	bool includes_vector_op = false;

	std::string specific_side_effects;
	std::string specific_side_effects_op_type;
};

class ZAM_UnaryOpTemplate : ZAM_OpTemplate {
public:
	ZAM_UnaryOpTemplate(std::string _base_name)
	: ZAM_OpTemplate(_base_name) { }

	bool HasDirectOp() const		{ return direct_op.size() > 0; }
	void SetDirectOp(std::string d_o)	{ direct_op = std::move(d_o); }
	const std::string& GetDirectOp() const	{ return direct_op; }

	bool NoConst() const			{ return no_const; }
	void SetNoConst()			{ no_const = true; }
	int Arity() const override		{ return 1; }

private:
	std::string direct_op;
	bool no_const = false;
};

class ZAM_DirectUnaryOpTemplate : ZAM_OpTemplate {
public:
	ZAM_DirectUnaryOpTemplate(std::string _base_name)
	: ZAM_OpTemplate(_base_name) { }

};

class ZAM_AssignOpTemplate : ZAM_OpTemplate {
public:
	ZAM_AssignOpTemplate(std::string _base_name)
	: ZAM_OpTemplate(_base_name) { }

};

class ZAM_ExprOpTemplate : ZAM_OpTemplate {
public:
	ZAM_ExprOpTemplate(std::string _base_name)
	: ZAM_OpTemplate(_base_name) { }

	bool IncludesFieldOp() const override	{ return true; }

	int TypeSelector() const	{ return type_selector; }
	void SetTypeSelector(int ts)	{ type_selector = ts; }

	void AddEvalSet(ZAM_ExprType et, std::string ev)
		{ eval_set[et].emplace_back(std::move(ev)); }
	void AddEvalSet(ZAM_ExprType et1, ZAM_ExprType et2, std::string ev)
		{ eval_mixed_set[et1][et2].emplace_back(std::move(ev)); }

	bool HasPreEval() const			{ return pre_eval.size() > 0; }
	void SetPreEval(std::string pe)		{ pre_eval = std::move(pe); }
	const std::string GetPreEval() const	{ return pre_eval; }

private:
	std::unordered_map<ZAM_ExprType, std::vector<std::string>> eval_set;
	std::unordered_map<ZAM_ExprType,
	 std::unordered_map<ZAM_ExprType, std::vector<std::string>>>
	  eval_mixed_set;

	// If non-zero, code to generate prior to evaluating the expression.
	std::string pre_eval;

	// If non-zero, specifies which operand to use to determine
	// the result type of the expression.
	int type_selector = 0;
};

class ZAM_UnaryExprOpTemplate : ZAM_ExprOpTemplate {
public:
	ZAM_UnaryExprOpTemplate(std::string _base_name)
	: ZAM_ExprOpTemplate(_base_name) { }

	int Arity() const override		{ return 1; }
};

class ZAM_BinaryExprOpTemplate : ZAM_ExprOpTemplate {
public:
	ZAM_BinaryExprOpTemplate(std::string _base_name)
	: ZAM_ExprOpTemplate(_base_name) { }

	int Arity() const override		{ return 2; }
};

class ZAM_RelationalExprOpTemplate : ZAM_BinaryExprOpTemplate {
public:
	ZAM_RelationalExprOpTemplate(std::string _base_name)
	: ZAM_BinaryExprOpTemplate(_base_name) { }
};

class ZAM_InternalBinaryOpTemplate : ZAM_BinaryExprOpTemplate {
public:
	ZAM_InternalBinaryOpTemplate(std::string _base_name)
	: ZAM_BinaryExprOpTemplate(_base_name) { }

	bool IsInternal() const override	{ return true; }

	void SetOp1Accessor(std::string accessor)
		{ op1_accessor = std::move(accessor); }
	void SetOp2Accessor(std::string accessor)
		{ op2_accessor = std::move(accessor); }
	void SetOpAccessor(std::string accessor)
		{
		SetOp1Accessor(accessor); 
		SetOp2Accessor(std::move(accessor));
		}

private:
	std::string op1_accessor;
	std::string op2_accessor;
};

class ZAM_InternalOpTemplate : ZAM_OpTemplate {
public:
	ZAM_InternalOpTemplate(std::string _base_name)
	: ZAM_OpTemplate(_base_name) { }

	bool IsInternal() const override	{ return true; }
	bool HasSideEffects() const override	{ return true; }
};

class ZAM_InternalAssignOpTemplate : ZAM_InternalOpTemplate {
public:
	ZAM_InternalAssignOpTemplate(std::string _base_name)
	: ZAM_InternalOpTemplate(_base_name) { }
};
