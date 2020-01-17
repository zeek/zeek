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

class Func : public BroObj {
public:

	enum Kind { BRO_FUNC, BUILTIN_FUNC };

	explicit Func(Kind arg_kind);

	~Func() override;

	virtual int IsPure() const = 0;
	function_flavor Flavor() const	{ return FType()->Flavor(); }

	struct Body {
		Stmt* stmts;
		int priority;
		bool operator<(const Body& other) const
			{ return priority > other.priority; } // reverse sort
	};

	const vector<Body>& GetBodies() const	{ return bodies; }
	bool HasBodies() const	{ return bodies.size(); }

	// virtual Val* Call(ListExpr* args) const = 0;
	virtual Val* Call(val_list* args, Frame* parent = 0) const = 0;

	// Add a new event handler to an existing function (event).
	virtual void AddBody(Stmt* new_body, id_list* new_inits,
			     size_t new_frame_size, int priority = 0);

	virtual void SetScope(Scope* newscope)	{ scope = newscope; }
	virtual Scope* GetScope() const		{ return scope; }

	virtual FuncType* FType() const { return type->AsFuncType(); }

	Kind GetKind() const	{ return kind; }

	const char* Name() const { return name.c_str(); }
	void SetName(const char* arg_name)	{ name = arg_name; }

	void Describe(ODesc* d) const override = 0;
	virtual void DescribeDebug(ODesc* d, const val_list* args) const;

	virtual Func* DoClone();

	virtual TraversalCode Traverse(TraversalCallback* cb) const;

	uint32_t GetUniqueFuncID() const { return unique_id; }
	static Func* GetFuncPtrByID(uint32_t id)
		{ return id >= unique_ids.size() ? 0 : unique_ids[id]; }

protected:
	Func();

	// Copies this function's state into other.
	void CopyStateInto(Func* other) const;

	// Helper function for handling result of plugin hook.
	std::pair<bool, Val*> HandlePluginResult(std::pair<bool, Val*> plugin_result, val_list* args, function_flavor flavor) const;

	vector<Body> bodies;
	Scope* scope;
	Kind kind;
	BroType* type;
	string name;
	uint32_t unique_id;
	static vector<Func*> unique_ids;
};


class BroFunc : public Func {
public:
	BroFunc(ID* id, Stmt* body, id_list* inits, size_t frame_size, int priority);
	~BroFunc() override;

	int IsPure() const override;
	Val* Call(val_list* args, Frame* parent) const override;

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

	void Describe(ODesc* d) const override;

protected:
	BroFunc() : Func(BRO_FUNC)	{}
	Stmt* AddInits(Stmt* body, id_list* inits);

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
};

typedef Val* (*built_in_func)(Frame* frame, val_list* args);

class BuiltinFunc : public Func {
public:
	BuiltinFunc(built_in_func func, const char* name, int is_pure);
	~BuiltinFunc() override;

	int IsPure() const override;
	Val* Call(val_list* args, Frame* parent) const override;
	built_in_func TheFunc() const	{ return func; }

	void Describe(ODesc* d) const override;

protected:
	BuiltinFunc()	{ func = 0; is_pure = 0; }

	built_in_func func;
	int is_pure;
};


extern void builtin_error(const char* msg, BroObj* arg = 0);
extern void init_builtin_funcs();
extern void init_builtin_funcs_subdirs();

extern bool check_built_in_call(BuiltinFunc* f, CallExpr* call);

struct CallInfo {
	const CallExpr* call;
	const Func* func;
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

extern std::string render_call_stack();

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;
