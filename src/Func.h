// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include <memory>

#include <broker/data.hh>
#include <broker/expected.hh>

#include "BroList.h"
#include "Obj.h"
#include "Debug.h"
#include "Frame.h"

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

class FuncOverload {
public:

	FuncOverload();

	FuncOverload(Func* func, FuncType* type);

	virtual ~FuncOverload();

	virtual int IsPure() const = 0;

	virtual Val* Call(val_list* args, Frame* parent = 0) const = 0;

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

// TODO: can maybe restructure Overloads to inherit from this again?
class Func : public BroObj {
public:

	enum Kind { BRO_FUNC, BUILTIN_FUNC };

	explicit Func(Kind arg_kind, std::string arg_name);

	~Func() override;

	const char* Name() const
		{ return name.c_str(); }

	Kind GetKind() const
		{ return kind; }

	const std::vector<FuncOverload*>& GetOverloads() const
		{ return overloads; }

	std::vector<FuncOverload*>& GetOverloads()
		{ return overloads; }

	// Add a new event handler to an existing function (event).
	virtual void AddBody(Stmt* new_body, id_list* new_inits,
			     size_t new_frame_size, int priority = 0);
	Val* Call(val_list* args, Frame* parent = 0) const;

	// TODO: get rid of this ? mark deprecated
	function_flavor Flavor() const
		{
		// TODO: really we should be storing the full FuncType here, so can
		// grab flavor from that ?
		assert(overloads.size() >= 1);
		return overloads[0]->GetType()->Flavor();
		}

	// TODO: get rid of this ? marke deprecated
	const std::vector<FuncBody>& GetBodies() const;

	// TODO: get rid of this ? mark deprecated
	bool HasBodies() const;

	// TODO: mark deprecated
	Scope* GetScope() const;

	// TODO: get rid of this ? mark deprecated
	FuncType* FType() const
		{
		assert(overloads.size() == 1);
		return overloads[0]->GetType();
		}

	virtual Func* DoClone();

	virtual TraversalCode Traverse(TraversalCallback* cb) const;

	uint32_t GetUniqueFuncID() const { return unique_id; }
	static Func* GetFuncPtrByID(uint32_t id)
		{ return id >= unique_ids.size() ? 0 : unique_ids[id]; }

	// TODO: could we change hashing to use the function name ?
	uint32 GetUniqueFuncID() const
		{ return unique_id; }

	// TODO: could we change hashing to use the function name ?
	static Func* GetFuncPtrByID(uint32 id)		

	void Describe(ODesc* d) const override;

	// Copies this function's state into other.
	void CopyStateInto(Func* other) const;

	// Helper function for handling result of plugin hook.
	std::pair<bool, Val*> HandlePluginResult(std::pair<bool, Val*> plugin_result, val_list* args, function_flavor flavor) const;

	void DescribeDebug(ODesc* d, const val_list* args) const;

	TraversalCode Traverse(TraversalCallback* cb) const;

	void AddOverload(FuncOverload* fo);

protected:

	Kind kind;
	string name;
	uint32_t unique_id;
	static vector<Func*> unique_ids;
	uint32 unique_id;
	std::vector<FuncOverload*> overloads;
	static std::vector<Func*> unique_ids;
};

class BroFunc : public FuncOverload {
public:

	BroFunc(ID* id, Stmt* body, id_list* inits, size_t frame_size, int priority);
	BroFunc(Func* f, BroType* type, Stmt* body, id_list* inits, int frame_size,
	        int priority, Scope* scope);
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

	void AddBody(Stmt* new_body, id_list* new_inits,
		     size_t new_frame_size, int priority) override;

	/** Sets this function's outer_id list. */
	void SetOuterIDs(id_list ids)
		{ outer_ids = std::move(ids); }

	Val* Call(val_list* args, Frame* parent = 0) const override;

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

	/**
	 * Clones this function along with its closures.
	 */
	Func* DoClone() override;

	/**
	 * Performs a selective clone of *f* using the IDs that were
	 * captured in the function's closure.
	 *
	 * @param f the frame to be cloned.
	 */
	void SetClosureFrame(Frame* f);

private:
	size_t frame_size;

	// List of the outer IDs used in the function.
	id_list outer_ids;
	// The frame the BroFunc was initialized in.
	Frame* closure = nullptr;
	bool weak_closure_ref = false;
	Scope* scope;
	int frame_size;
	std::vector<FuncBody> bodies;

	static Stmt* AddInits(Stmt* body, id_list* inits);
};

class BuiltinFunc : public FuncOverload {
public:
	BuiltinFunc(built_in_func func, const char* name, int is_pure);

	int IsPure() const override;

	Val* Call(val_list* args, Frame* parent = 0) const override;

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
	const FuncOverload* func;
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

extern vector<CallInfo> call_stack;
extern std::vector<CallInfo> call_stack;
extern std::string render_call_stack();

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;
