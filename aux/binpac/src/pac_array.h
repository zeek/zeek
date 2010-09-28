#ifndef pac_array_h
#define pac_array_h

#include "pac_common.h"
#include "pac_type.h"

// Fixed-length array and variable length sequence with an ending pattern

class ArrayType : public Type
{
public:
	ArrayType(Type *arg_elemtype, Expr *arg_length = 0);
	~ArrayType();

	bool DefineValueVar() const;
	string DataTypeStr() const;
	string DefaultValue() const	{ return "0"; }
	Type *ElementDataType() const;

	string EvalElement(const string &array, const string &index) const;

	void ProcessAttr(Attr *a);

	void Prepare(Env *env, int flags);

	void GenPubDecls(Output *out, Env *env);
	void GenPrivDecls(Output *out, Env *env);

	void GenInitCode(Output *out, Env *env);
	void GenCleanUpCode(Output *out, Env *env);

	int StaticSize(Env *env) const;

	void SetBoundaryChecked();
	void GenUntilInputCheck(Output *out_cc, Env *env);

	bool IsPointerType() const	{ return true; }

protected:
	void init();

	void DoGenParseCode(Output *out, Env *env, const DataPtr& data, int flags);
	void GenDynamicSize(Output *out, Env *env, const DataPtr& data);
	void GenArrayLength(Output *out_cc, Env *env, const DataPtr& data);
	string GenArrayInit(Output *out_cc, Env *env, bool known_array_length);
	void GenElementAssignment(Output *out_cc, Env *env,
		string const &array_str, bool use_vector);
	void GenUntilCheck(Output *out_cc, Env *env, 
		Expr *until_condition, bool delete_elem);

	bool ByteOrderSensitive() const 
		{ 
		return elemtype_->RequiresByteOrder(); 
		}
	bool RequiresAnalyzerContext();

	Type *DoClone() const;

	void DoMarkIncrementalInput();

	const ID *arraylength_var() const;
	const ID *elem_it_var() const;
	const ID *elem_var() const;
	const ID *elem_dataptr_var() const;
	const ID *elem_input_var() const;

protected:
	bool DoTraverse(DataDepVisitor *visitor);

private:
	Type *elemtype_;
	Expr *length_;

	string vector_str_;
	string datatype_str_;
	string end_of_array_loop_label_;

	Field *arraylength_var_field_;
	Field *elem_it_var_field_;
	Field *elem_var_field_;
	Field *elem_dataptr_var_field_;
	Field *elem_input_var_field_;

	// This does not come from &until, but is internally generated
	Expr *elem_dataptr_until_expr_;

	Expr *attr_generic_until_expr_;
	Expr *attr_until_element_expr_;
	Expr *attr_until_input_expr_;
};

#endif  // pac_array_h
