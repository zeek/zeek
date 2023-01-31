#ifndef pac_case_h
#define pac_case_h

#include "pac_common.h"
#include "pac_field.h"
#include "pac_id.h"
#include "pac_type.h"

class CaseType : public Type
	{
public:
	CaseType(Expr* index, CaseFieldList* cases);
	~CaseType() override;

	void AddCaseField(CaseField* f);

	bool DefineValueVar() const override;
	string DataTypeStr() const override;
	string DefaultValue() const override;

	void Prepare(Env* env, int flags) override;

	void GenPubDecls(Output* out, Env* env) override;
	void GenPrivDecls(Output* out, Env* env) override;

	void GenInitCode(Output* out, Env* env) override;
	void GenCleanUpCode(Output* out, Env* env) override;

	int StaticSize(Env* env) const override;

	void SetBoundaryChecked() override;

	Type* ValueType() const;

	Expr* IndexExpr() const { return index_expr_; }

	bool IsPointerType() const override { return ValueType()->IsPointerType(); }

protected:
	void DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags) override;
	void GenDynamicSize(Output* out, Env* env, const DataPtr& data) override;
	Type* DoClone() const override { return nullptr; }
	void DoMarkIncrementalInput() override;

	bool ByteOrderSensitive() const override;

	Expr* index_expr_;
	ID* index_var_;
	CaseFieldList* cases_;

	typedef map<const ID*, CaseField*, ID_ptr_cmp> member_map_t;
	member_map_t member_map_;
	};

class CaseField : public Field
	{
public:
	CaseField(ExprList* index, ID* id, Type* type);
	~CaseField() override;

	CaseType* case_type() const { return case_type_; }
	void set_case_type(CaseType* t) { case_type_ = t; }

	ExprList* index() const { return index_; }

	const char* lvalue() const { return type_->lvalue(); }

	const char* CaseStr(Env* env);
	void set_index_var(const ID* var) { index_var_ = var; }

	void Prepare(Env* env) override;

	void GenPubDecls(Output* out, Env* env) override;

	void GenInitCode(Output* out, Env* env) override;
	void GenCleanUpCode(Output* out, Env* env) override;
	void GenParseCode(Output* out, Env* env, const DataPtr& data, const ID* size_var);

	int StaticSize(Env* env) const { return type_->StaticSize(env); }

	bool IsDefaultCase() const { return ! index_; }
	void SetBoundaryChecked() { type_->SetBoundaryChecked(); }

	bool RequiresByteOrder() const { return type_->RequiresByteOrder(); }
	bool RequiresAnalyzerContext() const override;

protected:
	bool DoTraverse(DataDepVisitor* visitor) override;

protected:
	CaseType* case_type_;
	ExprList* index_;
	const ID* index_var_;
	};

// Generate a list of "case X:" lines from index_list. Each index
// expression must be constant foldable.
void GenCaseStr(ExprList* index_list, Output* out_cc, Env* env, Type* switch_type);

#endif // pac_case_h
