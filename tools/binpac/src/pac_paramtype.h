#ifndef pac_paramtype_h
#define pac_paramtype_h

#include "pac_type.h"

// An instantiated type: ID + expression list
class ParameterizedType : public Type
	{
public:
	ParameterizedType(ID* type_id, ExprList* args);
	~ParameterizedType() override;

	Type* clone() const;

	string EvalMember(const ID* member_id) const override;
	// Env *member_env() const;

	void AddParamArg(Expr* arg);

	bool DefineValueVar() const override;
	string DataTypeStr() const override;
	string DefaultValue() const override { return "0"; }
	Type* MemberDataType(const ID* member_id) const override;

	// "throw_exception" specifies whether to throw an exception
	// if the referred data type is not found
	Type* ReferredDataType(bool throw_exception) const;

	void GenCleanUpCode(Output* out, Env* env) override;

	int StaticSize(Env* env) const override;

	bool IsPointerType() const override { return true; }

	bool ByteOrderSensitive() const override;
	bool RequiresAnalyzerContext() override;

	void GenInitCode(Output* out_cc, Env* env) override;

	string class_name() const;
	string EvalParameters(Output* out_cc, Env* env) const;

	BufferMode buffer_mode() const override;

protected:
	void GenNewInstance(Output* out, Env* env) override;

	bool DoTraverse(DataDepVisitor* visitor) override;
	Type* DoClone() const override;
	void DoMarkIncrementalInput() override;

private:
	ID* type_id_;
	ExprList* args_;
	bool checking_requires_analyzer_context_;

	void DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags) override;
	void GenDynamicSize(Output* out, Env* env, const DataPtr& data) override;
	};

#endif // pac_paramtype_h
