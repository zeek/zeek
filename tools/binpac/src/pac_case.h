#ifndef pac_case_h
#define pac_case_h

#include "pac_common.h"
#include "pac_field.h"
#include "pac_id.h"
#include "pac_type.h"

class CaseType : public Type
{
public:
	CaseType(Expr *index, CaseFieldList *cases);
	~CaseType();

	void AddCaseField(CaseField *f);

	bool DefineValueVar() const;
	string DataTypeStr() const;
	string DefaultValue() const;

	void Prepare(Env *env, int flags);

	void GenPubDecls(Output *out, Env *env);
	void GenPrivDecls(Output *out, Env *env);

	void GenInitCode(Output *out, Env *env);
	void GenCleanUpCode(Output *out, Env *env);

	int StaticSize(Env *env) const;

	void SetBoundaryChecked();

	Type *ValueType() const;

	bool IsPointerType() const	{ return ValueType()->IsPointerType(); }

protected:
	void DoGenParseCode(Output *out, Env *env, const DataPtr& data, int flags);
	void GenDynamicSize(Output *out, Env *env, const DataPtr& data);
	Type *DoClone() const 	{ return 0; }
	void DoMarkIncrementalInput();

	bool ByteOrderSensitive() const;

	Expr *index_expr_;
	ID *index_var_;
	CaseFieldList *cases_;

	typedef map<const ID*, CaseField*, ID_ptr_cmp> member_map_t;
	member_map_t member_map_;
};

class CaseField : public Field
{
public:
	CaseField(ExprList *index, ID *id, Type *type);
	~CaseField();

	CaseType *case_type() const	{ return case_type_; }
	void set_case_type(CaseType *t)	{ case_type_ = t; }

	ExprList *index() const		{ return index_; }

	const char *lvalue() const	{ return type_->lvalue(); }

	const char *CaseStr(Env *env);
	void set_index_var(const ID *var) { index_var_ = var; }
	
	void Prepare(Env *env);

	void GenPubDecls(Output *out, Env *env);

	void GenInitCode(Output *out, Env *env);
	void GenCleanUpCode(Output *out, Env *env);
	void GenParseCode(Output *out, Env *env, 
		const DataPtr& data, const ID *size_var);

	int StaticSize(Env *env) const 	{ return type_->StaticSize(env); }

	bool IsDefaultCase() const	{ return ! index_; }
	void SetBoundaryChecked()	{ type_->SetBoundaryChecked(); }

	bool RequiresByteOrder() const	{ return type_->RequiresByteOrder(); }
	bool RequiresAnalyzerContext() const;

protected:
	bool DoTraverse(DataDepVisitor *visitor);

protected:
	CaseType *case_type_;
	ExprList *index_;
	const ID *index_var_;
};

// Generate a list of "case X:" lines from index_list. Each index
// expression must be constant foldable.
void GenCaseStr(ExprList *index_list, Output *out_cc, Env *env);

#endif  // pac_case_h
