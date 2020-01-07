// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include <memory>

#include <broker/data.hh>
#include <broker/expected.hh>

#include "BroList.h"
#include "Obj.h"
//#include "Debug.h"
//#include "Frame.h"
#include "Type.h"
#include "Scope.h"
//#include "Stmt.h"

class Val;
class ListExpr;
class FuncType;
class Stmt;
class Frame;
class ID;
class CallExpr;
class Func;

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
	FuncImpl(ID* id, int i);
	FuncImpl(const char* name);

	virtual ~FuncImpl();

	virtual int IsPure() const = 0;

	virtual Val* Call(val_list* args, Frame* parent = 0) const = 0;

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

	virtual void Describe(ODesc* d) const = 0;

	bool HasFunc ()
		{ return func != nullptr; }

	void SetOverloadIndex (int i)
		{ overload_idx = i; }

	int GetOverloadIndex() const
		{ return overload_idx; }

	void SetFunc(Func* f);
	void SetType(FuncType* t);

	Func* GetFunc() const
		{ return func; }
	FuncType* GetType() const
		{ return type; }

	const char* Name() const;

	function_flavor Flavor() const;

protected:
	FuncImpl(Func* f, FuncType* t);
	Func* func = nullptr;
	int overload_idx = -1;
	FuncType* type;
};

class Func : public BroObj {
public:

	explicit Func(ID* id);

	~Func() override;

	const char* Name() const { return name.c_str(); }
	void SetName(const char* arg_name)	{ name = arg_name; }

	function_flavor Flavor() const
		{ return type->Flavor(); }

	const std::vector<FuncImpl*>& Overloads() const
		{ return overloads; }

	FuncImpl* GetOverload(int idx) const;

	int AddOverload(FuncImpl* impl);

	void SetOverload(int idx, FuncImpl* impl);

	// Add a new event handler to an existing function (event).
	//virtual void AddBody(Stmt* new_body, id_list* new_inits,
	//		     size_t new_frame_size, int priority = 0);
	Val* Call(val_list* args, Frame* parent = 0, int overload_idx = -1) const;

	// TODO: get rid of this ?
	const std::vector<FuncBody>& GetBodies() const;

	// TODO: get rid of this ?
	bool HasBodies() const;

	// TODO: get rid of this ?
	Scope* GetScope() const;

	// TODO: get rid of this ? mark deprecated
	FuncType* FType() const
		{
		//assert(overloads.size() == 1);
		return type;
		}

	virtual Func* DoClone();

	virtual TraversalCode Traverse(TraversalCallback* cb) const;

	static Func* GetFuncPtrByID(uint32_t id)
		{ return id >= unique_ids.size() ? 0 : unique_ids[id]; }

	// TODO: could we change hashing to use the function name ?
	uint32_t GetUniqueFuncID() const
		{ return unique_id; }

	void Describe(ODesc* d) const override;

	// Helper function for handling result of plugin hook.
	std::pair<bool, Val*> HandlePluginResult(std::pair<bool, Val*> plugin_result, val_list* args, function_flavor flavor) const;

	void DescribeDebug(ODesc* d, const val_list* args) const;

protected:
	Func(std::string n, FuncType* t);
	FuncType* type;
	std::string name;
	uint32_t unique_id;
	std::vector<FuncImpl*> overloads;
	static std::vector<Func*> unique_ids;
};

class BroFunc : public FuncImpl {
public:
	BroFunc(ID* id, Stmt* body, id_list* inits, size_t frame_size, int priority, Scope* scope);
	~BroFunc() override;

	int IsPure() const override;

	/**
	 * Adds adds a closure to the function. Closures are cloned and
	 * future calls to BroFunc methods will not modify *f*.
	 *
	 * @param ids IDs that are captured by the closure.
	 * @param f the closure to be captured.
	 */
	void AddClosure(id_list ids, Frame* f);

	/**
	 * Replaces the current closure with one built from *data*
	 *
	 * @param data a serialized closure
	 */
	bool UpdateClosure(const broker::vector& data);

	/**
	 * If the function's closure is a weak reference to the given frame,
	 * upgrade to a strong reference of a shallow clone of that frame.
	 */
	bool StrengthenClosureReference(Frame* f);

	/**
	 * Serializes this function's closure.
	 *
	 * @return a serialized version of the function's closure.
	 */
	broker::expected<broker::data> SerializeClosure() const;

	/** Sets this function's outer_id list. */
	void SetOuterIDs(id_list ids)
		{ outer_ids = std::move(ids); }

	Val* Call(val_list* args, Frame* parent = 0) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	void Describe(ODesc* d) const override;

	// Typically used to add new event handler to existing event.
	void AddBody(Stmt* new_body, id_list* new_inits, int new_frame_size,
	             int priority, Scope* scope);

	// Copies this function's state into other.
	void CopyStateInto(BroFunc* other) const;

	Scope* GetScope() const
		{ return scope; }

	void SetScope (Scope* s)
		{ scope = s; }

	const std::vector<FuncBody>& GetBodies() const
		{ return bodies; }

	// TODO: Get this function on the FuncImpl level
	/**
	 * Clones this function along with its closures.
	 */
	BroFunc* DoClone();
private:
	friend class Func;

	/**
	 * Performs a selective clone of *f* using the IDs that were
	 * captured in the function's closure.
	 *
	 * @param f the frame to be cloned.
	 */
	void SetClosureFrame(Frame* f);
	size_t frame_size;

	// List of the outer IDs used in the function.
	id_list outer_ids;
	// The frame the BroFunc was initialized in.
	Frame* closure = nullptr;
	bool weak_closure_ref = false;
	Scope* scope;
	std::vector<FuncBody> bodies;

	static Stmt* AddInits(Stmt* body, id_list* inits);

protected:
	BroFunc (Func* f, FuncType* t);
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

// Struct that collects all the specifics defining a Func. Used for BroFuncs
// with closures.
struct function_ingredients {

	// Gathers all of the information from a scope and a function body needed
	// to build a function.
	function_ingredients(Scope* scope, Stmt* body);

	~function_ingredients();

	ID* id;
	Stmt* body;
	id_list* inits;
	int frame_size;
	int priority;
	Scope* scope;
};

extern std::vector<CallInfo> call_stack;
extern std::string render_call_stack();

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;
