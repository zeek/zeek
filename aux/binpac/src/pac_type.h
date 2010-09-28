#ifndef pac_type_h
#define pac_type_h

#include <map>
using namespace std;

#include "pac_common.h"
#include "pac_datadep.h"
#include "pac_dbg.h"

class Type : public Object, public DataDepElement
{
public:
	enum TypeType {
		UNDEF = -1,
		EMPTY,
		BUILTIN,
		PARAMETERIZED,
		RECORD,
		CASE,
		ARRAY,
		STRING,
		EXTERN,
		DUMMY,
	};

	explicit Type(TypeType tot);
	virtual ~Type();

	Type *Clone() const;

	// Type of type
	TypeType tot() const			{ return tot_; }

	////////////////////////////////////////
	// Code generation
	virtual void Prepare(Env *env, int flags);

	// Flag(s) for Prepare()
	static const int TO_BE_PARSED = 1;

	virtual void GenPubDecls(Output *out, Env *env);
	virtual void GenPrivDecls(Output *out, Env *env);

	virtual void GenInitCode(Output *out, Env *env);
	virtual void GenCleanUpCode(Output *out, Env *env);

	void GenPreParsing(Output *out, Env *env);
	void GenParseCode(Output *out, Env *env, const DataPtr& data, int flags);

	////////////////////////////////////////
	// TODO: organize the various methods below

	// The LValue string of the variable defined by the type. 
	// For example, if the type defines a record field, the 
	// lvalue is the member variable corresponding to the field; 
	// if the type appears in a type decl, then the lvalue is the
	// default value var.
	//
	const char *lvalue() const		{ return lvalue_.c_str(); }

	// The TypeDecl that defined the type.
	//
	const TypeDecl *type_decl() const	{ return type_decl_; }
	void set_type_decl(const TypeDecl *decl, bool declared_as_type);

	// Returns whether the type appears in a type declaration
	// (true) or as type specification of a field (false).
	//
	bool declared_as_type() const		{ return declared_as_type_; }

	// The ID of the decl in which the type appear. 
	//
	const ID *decl_id() const;

	Env *env() const			{ return env_; }

	string EvalByteOrder(Output *out_cc, Env *env) const;

	virtual string EvalMember(const ID *member_id) const;
	virtual string EvalElement(const string &array, 
	                           const string &index) const;

	// The variable defined by the type
	const ID *value_var() const		{ return value_var_; }
	void set_value_var(const ID *arg_id, int arg_id_type);

	bool anonymous_value_var() const	{ return anonymous_value_var_; }

	const ID *size_var() const;

	// Adds a variable to env to represent the size of this type.
	// Returns false if we do not need a size variable (because 
	// the type has a static size) or the size variable is already added.
	bool AddSizeVar(Output *out, Env *env);

	const ID *parsing_state_var() const;

	const ID *has_value_var() const;

	void AddField(Field *f);

	void AddCheck(Expr *expr)		{ /* TODO */ }

	virtual bool DefineValueVar() const = 0;

	// Returns C++ datatype string
	virtual string DataTypeStr() const = 0;

	// Returns const reference of the C++ data type (unless the type
	// is numeric or pointer)
	string DataTypeConstRefStr() const
		{
		string data_type = DataTypeStr();
		if ( ! IsPointerType() && ! IsNumericType() )
			data_type += " const &";
		return data_type;
		}

	// Returns a default value for the type
	virtual string DefaultValue() const	
		{ 
		ASSERT(0); return "@@@";
		}

	// Returns the data type of the member field/case
	virtual Type *MemberDataType(const ID *member_id) const;

	// Returns the data type of the element type of an array
	virtual Type *ElementDataType() const;

	// Whether the type needs clean-up at deallocation.
	bool NeedsCleanUp() const;

	// Whether byte order must be determined before parsing the type.
	bool RequiresByteOrder() const;

	// Whether class of the type requires a parameter of analyzer context. 
	virtual bool RequiresAnalyzerContext();

	virtual bool IsPointerType() const = 0;
	virtual bool IsNumericType() const	{ return false; }
	bool IsEmptyType() const;

	////////////////////////////////////////
	// Attributes
	virtual void ProcessAttr(Attr *a);

	bool  attr_chunked() const		{ return attr_chunked_; }
	Expr *attr_byteorder_expr() const	{ return attr_byteorder_expr_; }
	Expr *attr_if_expr() const		{ return attr_if_expr_; }
	// TODO: generate the length expression automatically.
	Expr *attr_length_expr() const		{ return attr_length_expr_; }
	bool  attr_refcount() const		{ return attr_refcount_; }
	bool  attr_transient() const		{ return attr_transient_; }

	// Whether the value remains valid outside the parse function
	bool persistent() const
		{
		return ! attr_transient() && ! attr_chunked();
		}

	void SetUntilCheck(ArrayType *t)	{ array_until_input_ = t; }

	////////////////////////////////////////
	// Size and boundary checking
	virtual int StaticSize(Env *env) const = 0;
	string DataSize(Output *out, Env *env, const DataPtr& data);

	bool boundary_checked() const		{ return boundary_checked_; }
	virtual void SetBoundaryChecked() 	{ boundary_checked_ = true; }
	void GenBoundaryCheck(Output *out, Env *env, const DataPtr& data);

	////////////////////////////////////////
	// Handling incremental input
	// 
	// There are two ways to handle incremental input: (1) to
	// buffer the input before parsing; (2) to parse incrementally.
	// 
	// The type must be "bufferable" for (1). While for (2),
	// each member of the type must be able to handle incremental
	// input.

	void MarkIncrementalInput();
	virtual void DoMarkIncrementalInput();

	// Whether the type may receive incremental input
	bool incremental_input() const		{ return incremental_input_; }

	// Whether parsing should also be incremental
	bool incremental_parsing() const	{ return incremental_parsing_; }

	// Whether we should buffer the input
	bool buffer_input() const		{ return buffer_input_; }

	// Whether parsing of the type is completed
	const ID *parsing_complete_var() const;
	string parsing_complete(Env *env) const;

	// Whether the input is bufferable
	bool Bufferable() const;
	bool BufferableByLength() const;
	bool BufferableByLine() const;

	enum BufferMode {
		NOT_BUFFERABLE,
		BUFFER_NOTHING,		// for type "empty"
		BUFFER_BY_LENGTH,
		BUFFER_BY_LINE,
	};
	virtual BufferMode buffer_mode() const;

	void GenBufferConfiguration(Output *out, Env *env);

	int InitialBufferLength() const;

protected:
	virtual void GenNewInstance(Output *out, Env *env) {}

	virtual bool ByteOrderSensitive() const = 0;

	bool NeedsBufferingStateVar() const;

	void GenBufferingLoop(Output* out_cc, Env* env, int flags);
	void GenParseBuffer(Output* out_cc, Env* env, int flags);
	void GenParseCode2(Output* out_cc, Env* env, const DataPtr& data, int flags);
	void GenParseCode3(Output* out_cc, Env* env, const DataPtr& data, int flags);

	virtual void DoGenParseCode(Output *out, Env *env,
		const DataPtr& data, 
		int flags) = 0;

	string EvalLengthExpr(Output* out_cc, Env* env);

	// Generate code for computing the dynamic size of the type
	virtual void GenDynamicSize(Output *out, Env *env,
		const DataPtr& data) = 0;

	bool DoTraverse(DataDepVisitor *visitor);

	virtual Type *DoClone() const = 0;

protected:
	TypeType tot_;
	const TypeDecl *type_decl_;
	bool declared_as_type_;
	const ID *type_decl_id_;
	Env *env_;

	const ID *value_var_;
	bool anonymous_value_var_;	// whether the ID is anonymous

	string data_id_str_;
	int value_var_type_;
	Field *size_var_field_;
	char *size_expr_;
	bool boundary_checked_;
	string lvalue_;
	FieldList *fields_;

	bool incremental_input_;
	bool incremental_parsing_;
	bool buffer_input_;

	// A boolean variable on whether parsing of the type is completed
	Field *parsing_complete_var_field_;

	// An integer variable holding the parsing state
	Field *parsing_state_var_field_;

	Field *buffering_state_var_field_;

	// The array type with &until($input...) condition, if
	// "this" is the element type
	ArrayType *array_until_input_;

	// A "has_*" member var for fields with &if
	LetField *has_value_field_;

	// Attributes
	AttrList *attrs_;

	Expr *attr_byteorder_expr_;
	ExprList *attr_checks_;
	bool attr_chunked_;
	bool attr_exportsourcedata_;
	Expr *attr_if_expr_;
	Expr *attr_length_expr_;
	FieldList *attr_letfields_;
	Expr *attr_multiline_end_;
	bool attr_oneline_;
	bool attr_refcount_;
	Expr *attr_requires_;
	bool attr_restofdata_;
	bool attr_restofflow_;
	bool attr_transient_;

public:
	static void init();
	static bool CompatibleTypes(Type *type1, Type *type2);
	static void AddPredefinedType(const string &type_name, Type *type);
	static Type *LookUpByID(ID *id);

protected:
	typedef map<string, Type *> type_map_t;
	static type_map_t type_map_;
};

#endif  // pac_type_h
