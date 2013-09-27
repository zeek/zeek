#ifndef pac_paramtype_h
#define pac_paramtype_h

#include "pac_type.h"

// An instantiated type: ID + expression list
class ParameterizedType : public Type
{
public:
	ParameterizedType(ID *type_id, ExprList *args);
	~ParameterizedType();

	Type *clone() const;

	string EvalMember(const ID *member_id) const;
	// Env *member_env() const;

	void AddParamArg(Expr *arg);

	bool DefineValueVar() const;
	string DataTypeStr() const;
	string DefaultValue() const	{ return "0"; }
	Type *MemberDataType(const ID *member_id) const;

	// "throw_exception" specifies whether to throw an exception
	// if the referred data type is not found
	Type *ReferredDataType(bool throw_exception) const;

	void GenCleanUpCode(Output *out, Env *env);

	int StaticSize(Env *env) const;

	bool IsPointerType() const	{ return true; }

	bool ByteOrderSensitive() const;
	bool RequiresAnalyzerContext();

	void GenInitCode(Output *out_cc, Env *env);

	string class_name() const;
	string EvalParameters(Output *out_cc, Env *env) const;

	BufferMode buffer_mode() const;

protected:
	void GenNewInstance(Output *out, Env *env);

	bool DoTraverse(DataDepVisitor *visitor);
	Type *DoClone() const;
	void DoMarkIncrementalInput();

private:
	ID *type_id_;
	ExprList *args_;
	bool checking_requires_analyzer_context_;

	void DoGenParseCode(Output *out, Env *env, const DataPtr& data, int flags);
	void GenDynamicSize(Output *out, Env *env, const DataPtr& data);
};

#endif  // pac_paramtype_h
