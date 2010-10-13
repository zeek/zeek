#ifndef pac_id_h
#define pac_id_h

#include <map>
#include <string>
using namespace std;

#include "pac_common.h"
#include "pac_dbg.h"
#include "pac_utils.h"

// Classes handling identifiers.
// 
// ID -- name and location of definition of an ID
//
// IDRecord -- association of an ID, its definition type (const, global, temp, 
//   member, or union member), and its evaluation method. 
//
// Evaluatable -- interface for a variable or a field that needs be evaluated
//   before referenced.
//
// Env -- a mapping from ID names to their L/R-value expressions and evaluation
//   methods.

enum IDType {
	CONST,
	GLOBAL_VAR,
	TEMP_VAR,
	MEMBER_VAR,
	PRIV_MEMBER_VAR,
	UNION_VAR,
	STATE_VAR,
	MACRO,
	FUNC_ID,
	FUNC_PARAM,
};

class ID;
class IDRecord;
class Env;
class Evaluatable;

class ID : public Object
{
public:
	ID(const char *arg_name)
		: name(arg_name), anonymous_id_(false)
		{
		locname = nfmt("%s:%s", Location(), Name());
		}
	~ID()
		{
		delete locname;
		}

	bool operator==(ID const &x) const { return name == x.Name(); }

	const char *Name() const 	{ return name.c_str(); }
	const char *LocName() const 	{ return locname; }
	bool is_anonymous() const	{ return anonymous_id_; }

	ID *clone() const		{ return new ID(Name()); }

protected:
	string name;
	bool anonymous_id_;
	char *locname;
	friend class ID_ptr_cmp;

public:
	static ID *NewAnonymousID(const string &prefix);
private:
	static int anonymous_id_seq;
};

// A comparison operator for pointers to ID's.
class ID_ptr_cmp
{
public:
	bool operator()(const ID *const & id1, const ID *const & id2) const
		{
		ASSERT(id1);
		ASSERT(id2);
		return id1->name < id2->name;
		}
};

class IDRecord
{
public:
	IDRecord(Env *env, const ID *id, IDType id_type);
	~IDRecord();

	IDType GetType() const			{ return id_type; }

	void SetDataType(Type *type) 		{ data_type = type; }
	Type *GetDataType() const		{ return data_type; }

	void SetEvalMethod(Evaluatable *arg_eval) { eval = arg_eval; }
	void Evaluate(Output *out, Env *env);
	void SetEvaluated(bool v);
	bool Evaluated() const 			{ return evaluated; }

	void SetField(Field *f)			{ field = f; }
	Field *GetField() const			{ return field; }

	void SetConstant(int c);			
	bool GetConstant(int *pc) const;

	void SetMacro(Expr *expr);
	Expr *GetMacro() const;

	const char * RValue() const;
	const char * LValue() const;

protected:
	Env *env;
	const ID *id;
	IDType id_type;

	string rvalue;
	string lvalue;
	string setfunc;

	Type *data_type;

	Field *field;

	int constant;
	bool constant_set;

	Expr *macro;

	bool evaluated;
	bool in_evaluation;	// to detect cyclic dependence
	Evaluatable *eval;
};

class Evaluatable
{
public:
	virtual ~Evaluatable() {}
	virtual void GenEval(Output *out, Env *env) = 0;
};

class Env
{
public:
	Env(Env *parent_env, Object *context_object);
	~Env();

	bool allow_undefined_id() const		{ return allow_undefined_id_; }
	void set_allow_undefined_id(bool x)	{ allow_undefined_id_ = x; }

	bool in_branch() const			{ return in_branch_; }
	void set_in_branch(bool x)		{ in_branch_ = x; }

	void AddID(const ID *id, IDType id_type, Type *type);
	void AddConstID(const ID *id, const int c, Type *type = 0);
	void AddMacro(const ID *id, Expr *expr);

	// Generate a temp ID with a unique name
	ID *AddTempID(Type *type);

	IDType GetIDType(const ID *id) const;
	const char * RValue(const ID *id) const;
	const char * LValue(const ID *id) const;
	// const char *SetFunc(const ID *id) const;

	// Set evaluation method for the ID
	void SetEvalMethod(const ID *id, Evaluatable *eval);

	// Evaluate the ID according to the evaluation method. It
	// assumes the ID has an evaluation emthod. It does nothing
	// if the ID has already been evaluated.
	void Evaluate(Output *out, const ID *id);

	// Whether the ID has already been evaluated.
	bool Evaluated(const ID *id) const;

	// Set the ID as evaluated (or not).
	void SetEvaluated(const ID *id, bool v = true);

	void SetField(const ID *id, Field *field);
	Field *GetField(const ID *id) const;

	bool GetConstant(const ID *id, int *pc) const;

	Expr *GetMacro(const ID *id) const;

	Type *GetDataType(const ID *id) const;

	string DataTypeStr(const ID *id) const;

protected:
	IDRecord *lookup(const ID *id, 
	                 bool recursive, 
	                 bool raise_exception) const;

	void SetDataType(const ID *id, Type *type);
	void SetConstant(const ID *id, int constant);
	void SetMacro(const ID *id, Expr *macro);

private:
	Env *parent;
	Object *context_object_;
	typedef map<const ID*, IDRecord*, ID_ptr_cmp> id_map_t;
	id_map_t id_map;
	bool allow_undefined_id_;
	bool in_branch_;
};

extern const ID *default_value_var;
extern const ID *null_id;
extern const ID *null_byteseg_id;
extern const ID *begin_of_data;
extern const ID *end_of_data;
extern const ID *len_of_data;
extern const ID *byteorder_id;
extern const ID *bigendian_id;
extern const ID *littleendian_id;
extern const ID *unspecified_byteorder_id;
extern const ID *analyzer_context_id;
extern const ID *context_macro_id;
extern const ID *this_id;
extern const ID *sourcedata_id;
// extern const ID *sourcedata_begin_id;
// extern const ID *sourcedata_end_id;
extern const ID *connection_id;
extern const ID *upflow_id;
extern const ID *downflow_id;
extern const ID *dataunit_id;
extern const ID *flow_buffer_id;
extern const ID *element_macro_id;
extern const ID *cxt_connection_id;
extern const ID *cxt_flow_id;
extern const ID *input_macro_id;
extern const ID *parsing_state_id;
extern const ID *buffering_state_id;

extern void init_builtin_identifiers();
extern Env *global_env();

extern string set_function(const ID *id);

#endif // pac_id_h
