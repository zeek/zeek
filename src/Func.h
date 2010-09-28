// $Id: Func.h 6916 2009-09-24 20:48:36Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef func_h
#define func_h

#include "BroList.h"
#include "Obj.h"
#include "Debug.h"

class Val;
class ListExpr;
class FuncType;
class Stmt;
class Frame;
class ID;

class Func : public BroObj {
public:

	enum Kind { BRO_FUNC, BUILTIN_FUNC };

	Func(Kind arg_kind)
		{ scope = 0; kind = arg_kind; id = 0; return_value = 0; }

	virtual ~Func();

	virtual int IsPure() const = 0;
	int IsEvent() const	{ return FType()->IsEvent(); }

	struct Body {
		Stmt* stmts;
		int priority;
		bool operator<(const Body& other) const
			{ return priority > other.priority; } // reverse sort
	};

	virtual const vector<Body>& GetBodies() const	{ return bodies; }

	// virtual Val* Call(ListExpr* args) const = 0;
	virtual Val* Call(val_list* args, Frame* parent = 0) const = 0;

	// Add a new event handler to an existing function (event).
	virtual void AddBody(Stmt* new_body, id_list* new_inits,
				int new_frame_size, int priority = 0);

	virtual void SetScope(Scope* newscope)	{ scope = newscope; }
	virtual Scope* GetScope() const		{ return scope; }

	virtual FuncType* FType() const
		{
		return (FuncType*) id->Type()->AsFuncType();
		}

	Kind GetKind() const	{ return kind; }

	const ID* GetID() const { return id; }
	void SetID(ID *arg_id);

	virtual void Describe(ODesc* d) const = 0;
	virtual void DescribeDebug(ODesc* d, const val_list* args) const;

	// This (un-)serializes only a single body (as given in SerialInfo).
	bool Serialize(SerialInfo* info) const;
	static Func* Unserialize(UnserialInfo* info);

	ID* GetReturnValueID() const;
	virtual TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	Func()	{ scope = 0; id = 0; return_value = 0; }

	DECLARE_ABSTRACT_SERIAL(Func);

	vector<Body> bodies;
	Scope* scope;
	Kind kind;
	ID* id;
	ID* return_value;
};


class BroFunc : public Func {
public:
	BroFunc(ID* id, Stmt* body, id_list* inits, int frame_size);
	~BroFunc();

	int IsPure() const;
	Val* Call(val_list* args, Frame* parent) const;

	void AddBody(Stmt* new_body, id_list* new_inits, int new_frame_size,
			int priority);

	int FrameSize() const {	return frame_size; }

	void Describe(ODesc* d) const;

protected:
	BroFunc() : Func(BRO_FUNC)	{}
	Stmt* AddInits(Stmt* body, id_list* inits);

	DECLARE_SERIAL(BroFunc);

	int frame_size;
};

typedef Val* (*built_in_func)(Frame* frame, val_list* args);

class BuiltinFunc : public Func {
public:
	BuiltinFunc(built_in_func func, const char* name, int is_pure);
	~BuiltinFunc();

	int IsPure() const;
	Val* Call(val_list* args, Frame* parent) const;
	const char* Name() const	{ return name; }
	built_in_func TheFunc() const	{ return func; }

	void Describe(ODesc* d) const;

protected:
	BuiltinFunc()	{ func = 0; name = 0; is_pure = 0; }

	DECLARE_SERIAL(BuiltinFunc);

	built_in_func func;
	const char* name;
	int is_pure;
};


extern void builtin_run_time(const char* msg, BroObj* arg = 0);
extern void init_builtin_funcs();

extern bool check_built_in_call(BuiltinFunc* f, CallExpr* call);

// This global is set prior to the interpreter making a function call.
// It's there so that built-in functions can access the location information
// associated with a call when reporting error messages.
extern const Expr* calling_expr;

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;

#endif
