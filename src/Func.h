// See the file "COPYING" in the main distribution directory for copyright.

#ifndef func_h
#define func_h

#include <utility>
#include <memory> // std::shared_ptr, std::unique_ptr

#include "BroList.h"
#include "Obj.h"
#include "Debug.h"
#include "Frame.h"
// #include "Val.h"

class Val;
class ListExpr;
class FuncType;
class Stmt;
class Frame;
class ID;
class CallExpr;

struct CloneState;

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
				int new_frame_size, int priority = 0);

	virtual void SetScope(Scope* newscope)	{ scope = newscope; }
	virtual Scope* GetScope() const		{ return scope; }

	virtual FuncType* FType() const { return type->AsFuncType(); }

	Kind GetKind() const	{ return kind; }

	const char* Name() const { return name.c_str(); }
	void SetName(const char* arg_name)	{ name = arg_name; }

	void Describe(ODesc* d) const override = 0;
	virtual void DescribeDebug(ODesc* d, const val_list* args) const;

	virtual Val* DoClone();

	virtual TraversalCode Traverse(TraversalCallback* cb) const;

	uint32 GetUniqueFuncID() const { return unique_id; }
	static Func* GetFuncPtrByID(uint32 id)
		{ return id >= unique_ids.size() ? 0 : unique_ids[id]; }

protected:
	Func();

	// Helper function for handling result of plugin hook.
	std::pair<bool, Val*> HandlePluginResult(std::pair<bool, Val*> plugin_result, val_list* args, function_flavor flavor) const;

	vector<Body> bodies;
	Scope* scope;
	Kind kind;
	BroType* type;
	string name;
	uint32 unique_id;
	static vector<Func*> unique_ids;
};


class BroFunc : public Func {
public:
	BroFunc(ID* id, Stmt* body, id_list* inits, int frame_size, int priority);
	~BroFunc() override;

	int IsPure() const override;
	Val* Call(val_list* args, Frame* parent) const override;

        void AddClosure(std::shared_ptr<id_list> ids, Frame* f);
	void AddBody(Stmt* new_body, id_list* new_inits, int new_frame_size,
			int priority) override;

	void fsets();

	Val* DoClone() override;

	int FrameSize() const {	return frame_size; }

	void Describe(ODesc* d) const override;

protected:
	BroFunc() : Func(BRO_FUNC)	{}
	Stmt* AddInits(Stmt* body, id_list* inits);

	int frame_size;

private:
	// Shifts the offsets of each id in "idl" by "shift".
	static void ShiftOffsets(int shift, std::shared_ptr<id_list> idl);

	// Makes a deep copy of the input frame and captures it.
	void SetClosureFrame(Frame* f);

	void SetOuterIDs(std::shared_ptr<id_list> ids)
		{ outer_ids = std::move(ids); }

        // List of the outer IDs used in the function. Shared becase other instances
        // would like to use it as well.
	std::shared_ptr<id_list> outer_ids = nullptr;
	// The frame the Func was initialized in. This is not guaranteed to be
	// initialized and should be handled with care.
	Frame* closure = nullptr;
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

// Struct that collects the arguments for a Func.
// Used for BroFuncs with closures.
struct function_ingredients
	{
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

#endif
