// See the file "COPYING" in the main distribution directory for copyright.

#ifndef func_h
#define func_h

#include <utility>

#include "BroList.h"
#include "Obj.h"
#include "Debug.h"

class Val;
class ListExpr;
class FuncType;
class Stmt;
class Frame;
class ID;
class CallExpr;
class Func;
class FuncOverload;

typedef Val* (*built_in_func)(Frame* frame, val_list* args);

struct FuncBody {
	Stmt* stmts;
	int priority;
	bool operator<(const FuncBody& other) const
		{ return priority > other.priority; } // reverse sort
};

class FuncImpl : public BroObj {
public:

	FuncImpl(ID* id);
	FuncImpl(const char* name);

	virtual ~FuncImpl();

	virtual int IsPure() const = 0;

	virtual Val* Call(val_list* args, Frame* parent = 0) const = 0;

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

	virtual void Describe(ODesc* d) const = 0;

	Func* GetFunc() const
		{ return func; }

	FuncType* GetType() const
		{ return type; }

	const char* Name() const;

	function_flavor Flavor() const;

protected:

	Func* func;
	FuncType* type;
};

class Func : public BroObj {
public:

	explicit Func(ID* id);

	~Func() override;

	const char* Name() const
		{ return name.c_str(); }

	FuncType* FType() const
		{ return type; }

	function_flavor Flavor() const
		{ return type->Flavor(); }

	const std::vector<FuncOverload*>& Overloads() const
		{ return type->Overloads(); }

	Val* Call(val_list* args, Frame* parent = 0, int overload_idx = -1) const;

	// TODO: get rid of this ?
	const std::vector<FuncBody>& GetBodies() const;

	// TODO: get rid of this ?
	bool HasBodies() const;

	// TODO: get rid of this ?
	Scope* GetScope() const;

	// TODO: could we change hashing to use the function name ?
	uint32 GetUniqueFuncID() const
		{ return unique_id; }

	// TODO: could we change hashing to use the function name ?
	static Func* GetFuncPtrByID(uint32 id)
		{ return id >= unique_ids.size() ? 0 : unique_ids[id]; }

	void Describe(ODesc* d) const override;

	void DescribeDebug(ODesc* d, const val_list* args) const;

	TraversalCode Traverse(TraversalCallback* cb) const;

protected:

	FuncType* type;
	string name;
	uint32 unique_id;

	static std::vector<Func*> unique_ids;
};

class BroFunc : public FuncImpl {
public:
	BroFunc(ID* id, Stmt* body, id_list* inits, int frame_size,
	        int priority, Scope* scope);

	~BroFunc() override;

	int IsPure() const override;

	Val* Call(val_list* args, Frame* parent = 0) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	void Describe(ODesc* d) const override;

	// Typically used to add new event handler to existing event.
	void AddBody(Stmt* new_body, id_list* new_inits, int new_frame_size,
	             int priority, Scope* scope);

	Scope* GetScope() const
		{ return scope; }

	const std::vector<FuncBody>& GetBodies() const
		{ return bodies; }

private:
	friend class Func;

	Scope* scope;
	int frame_size;
	std::vector<FuncBody> bodies;

	static Stmt* AddInits(Stmt* body, id_list* inits);
};

class BuiltinFunc : public FuncImpl {
public:
	BuiltinFunc(built_in_func func, const char* name, int is_pure);

	int IsPure() const override;

	Val* Call(val_list* args, Frame* parent = 0) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	void Describe(ODesc* d) const override;

	built_in_func InternalFunc() const
		{ return internal_func; }

private:

	built_in_func internal_func;
	int is_pure;
};

extern void builtin_error(const char* msg, BroObj* arg = 0);
extern void init_builtin_funcs();
extern void init_builtin_funcs_subdirs();

extern bool check_built_in_call(BuiltinFunc* f, CallExpr* call);

struct CallInfo {
	const CallExpr* call;
	const FuncImpl* func;
	const val_list* args;
};

extern std::vector<CallInfo> call_stack;

extern std::string render_call_stack();

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;

#endif
