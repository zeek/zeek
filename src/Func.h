// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include <memory>
#include <string>
#include <vector>
#include <tuple>
#include <type_traits>

#include <broker/data.hh>
#include <broker/expected.hh>

#include "BroList.h"
#include "Obj.h"
#include "IntrusivePtr.h"
#include "Type.h" /* for function_flavor */
#include "TraverseTypes.h"
#include "ZeekArgs.h"

class Val;
class FuncType;
class Frame;
class ID;
class Scope;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
FORWARD_DECLARE_NAMESPACED(CallExpr, zeek::detail);

class Func : public BroObj {
public:
	static inline const IntrusivePtr<Func> nil;

	enum Kind { BRO_FUNC, BUILTIN_FUNC };

	explicit Func(Kind arg_kind);

	~Func() override;

	virtual bool IsPure() const = 0;
	function_flavor Flavor() const	{ return GetType()->Flavor(); }

	struct Body {
		IntrusivePtr<zeek::detail::Stmt> stmts;
		int priority;
		bool operator<(const Body& other) const
			{ return priority > other.priority; } // reverse sort
	};

	const std::vector<Body>& GetBodies() const	{ return bodies; }
	bool HasBodies() const	{ return bodies.size(); }

	[[deprecated("Remove in v4.1. Use Invoke() instead.")]]
	Val* Call(val_list* args, Frame* parent = nullptr) const;

	/**
	 * Calls a Zeek function.
	 * @param args  the list of arguments to the function call.
	 * @param parent  the frame from which the function is being called.
	 * @return  the return value of the function call.
	 */
	virtual IntrusivePtr<Val> Invoke(zeek::Args* args,
	                                   Frame* parent = nullptr) const = 0;

	/**
	 * A version of Invoke() taking a variable number of individual arguments.
	 */
	template <class... Args>
	std::enable_if_t<
	  std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>,
	                        IntrusivePtr<Val>>,
	  IntrusivePtr<Val>>
	Invoke(Args&&... args) const
		{
		auto zargs = zeek::Args{std::forward<Args>(args)...};
		return Invoke(&zargs);
		}

	// Add a new event handler to an existing function (event).
	virtual void AddBody(IntrusivePtr<zeek::detail::Stmt> new_body,
	                     const std::vector<IntrusivePtr<ID>>& new_inits,
	                     size_t new_frame_size, int priority = 0);

	virtual void SetScope(IntrusivePtr<Scope> newscope);
	virtual Scope* GetScope() const		{ return scope.get(); }

	[[deprecated("Remove in v4.1.  Use GetType().")]]
	virtual FuncType* FType() const { return type.get(); }

	const IntrusivePtr<FuncType>& GetType() const
		{ return type; }

	Kind GetKind() const	{ return kind; }

	const char* Name() const { return name.c_str(); }
	void SetName(const char* arg_name)	{ name = arg_name; }

	void Describe(ODesc* d) const override = 0;
	virtual void DescribeDebug(ODesc* d, const zeek::Args* args) const;

	virtual IntrusivePtr<Func> DoClone();

	virtual TraversalCode Traverse(TraversalCallback* cb) const;

	uint32_t GetUniqueFuncID() const { return unique_id; }
	static const IntrusivePtr<Func>& GetFuncPtrByID(uint32_t id)
		{ return id >= unique_ids.size() ? Func::nil : unique_ids[id]; }

protected:
	Func();

	// Copies this function's state into other.
	void CopyStateInto(Func* other) const;

	// Helper function for checking result of plugin hook.
	void CheckPluginResult(bool handled, const IntrusivePtr<Val>& hook_result,
	                       function_flavor flavor) const;

	std::vector<Body> bodies;
	IntrusivePtr<Scope> scope;
	Kind kind;
	uint32_t unique_id;
	IntrusivePtr<FuncType> type;
	std::string name;
	static inline std::vector<IntrusivePtr<Func>> unique_ids;
};


class BroFunc final : public Func {
public:
	BroFunc(const IntrusivePtr<ID>& id, IntrusivePtr<zeek::detail::Stmt> body,
	        const std::vector<IntrusivePtr<ID>>& inits,
	        size_t frame_size, int priority);

	~BroFunc() override;

	bool IsPure() const override;
	IntrusivePtr<Val> Invoke(zeek::Args* args, Frame* parent) const override;

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

	void AddBody(IntrusivePtr<zeek::detail::Stmt> new_body,
	             const std::vector<IntrusivePtr<ID>>& new_inits,
	             size_t new_frame_size, int priority) override;

	/** Sets this function's outer_id list. */
	void SetOuterIDs(id_list ids)
		{ outer_ids = std::move(ids); }

	void Describe(ODesc* d) const override;

protected:
	BroFunc() : Func(BRO_FUNC)	{}
	IntrusivePtr<zeek::detail::Stmt> AddInits(IntrusivePtr<zeek::detail::Stmt> body,
	                                          const std::vector<IntrusivePtr<ID>>& inits);

	/**
	 * Clones this function along with its closures.
	 */
	IntrusivePtr<Func> DoClone() override;

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

/**
 * A simple wrapper class to use for the return value of BIFs so that
 * they may return either a Val* or IntrusivePtr<Val> (the former could
 * potentially be deprecated).
 */
class BifReturnVal {
public:

	template <typename T>
	BifReturnVal(IntrusivePtr<T> v) noexcept
		: rval(AdoptRef{}, v.release())
		{ }

	BifReturnVal(std::nullptr_t) noexcept;

	[[deprecated("Remove in v4.1.  Return an IntrusivePtr instead.")]]
	BifReturnVal(Val* v) noexcept;

	IntrusivePtr<Val> rval;
};

using built_in_func = BifReturnVal (*)(Frame* frame, const zeek::Args* args);

class BuiltinFunc final : public Func {
public:
	BuiltinFunc(built_in_func func, const char* name, bool is_pure);
	~BuiltinFunc() override;

	bool IsPure() const override;
	IntrusivePtr<Val> Invoke(zeek::Args* args, Frame* parent) const override;
	built_in_func TheFunc() const	{ return func; }

	void Describe(ODesc* d) const override;

protected:
	BuiltinFunc()	{ func = nullptr; is_pure = 0; }

	built_in_func func;
	bool is_pure;
};


extern void builtin_error(const char* msg);
extern void builtin_error(const char* msg, IntrusivePtr<Val>);
extern void builtin_error(const char* msg, BroObj* arg);
extern void init_builtin_funcs();
extern void init_builtin_funcs_subdirs();

extern bool check_built_in_call(BuiltinFunc* f, zeek::detail::CallExpr* call);

struct CallInfo {
	const zeek::detail::CallExpr* call;
	const Func* func;
	const zeek::Args& args;
};

// Struct that collects all the specifics defining a Func. Used for BroFuncs
// with closures.
struct function_ingredients {

	// Gathers all of the information from a scope and a function body needed
	// to build a function.
	function_ingredients(IntrusivePtr<Scope> scope, IntrusivePtr<zeek::detail::Stmt> body);

	IntrusivePtr<ID> id;
	IntrusivePtr<zeek::detail::Stmt> body;
	std::vector<IntrusivePtr<ID>> inits;
	int frame_size;
	int priority;
	IntrusivePtr<Scope> scope;
};

extern std::vector<CallInfo> call_stack;

extern std::string render_call_stack();

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;
