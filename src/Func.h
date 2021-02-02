// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include <memory>
#include <string>
#include <vector>
#include <tuple>
#include <type_traits>

#include "zeek/ZeekList.h"
#include "zeek/Stmt.h"
#include "zeek/Obj.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h" /* for function_flavor */
#include "zeek/TraverseTypes.h"
#include "zeek/ZeekArgs.h"
#include "zeek/BifReturnVal.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Scope, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(CallExpr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(FuncType, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);

namespace caf {
template <class> class expected;
}

namespace broker {
class data;
using vector = std::vector<data>;
using caf::expected;
}

namespace zeek {

namespace detail {

using ScopePtr = IntrusivePtr<Scope>;
using IDPtr = IntrusivePtr<ID>;
using StmtPtr = IntrusivePtr<Stmt>;

class ScriptFunc;

} // namespace detail

class Func;
using FuncPtr = IntrusivePtr<Func>;

class Func : public Obj {
public:

	static inline const FuncPtr nil;

	enum Kind { SCRIPT_FUNC, BUILTIN_FUNC };

	explicit Func(Kind arg_kind);

	~Func() override;

	virtual bool IsPure() const = 0;
	FunctionFlavor Flavor() const	{ return GetType()->Flavor(); }

	struct Body {
		detail::StmtPtr stmts;
		int priority;
		bool operator<(const Body& other) const
			{ return priority > other.priority; } // reverse sort
	};

	const std::vector<Body>& GetBodies() const	{ return bodies; }
	bool HasBodies() const	{ return bodies.size(); }

	/**
	 * Calls a Zeek function.
	 * @param args  the list of arguments to the function call.
	 * @param parent  the frame from which the function is being called.
	 * @return  the return value of the function call.
	 */
	virtual ValPtr Invoke(
		zeek::Args* args, detail::Frame* parent = nullptr) const = 0;

	/**
	 * A version of Invoke() taking a variable number of individual arguments.
	 */
	template <class... Args>
	std::enable_if_t<
		std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>,
		ValPtr>
	Invoke(Args&&... args) const
		{
		auto zargs = zeek::Args{std::forward<Args>(args)...};
		return Invoke(&zargs);
		}

	// Add a new event handler to an existing function (event).
	virtual void AddBody(detail::StmtPtr new_body,
	                     const std::vector<detail::IDPtr>& new_inits,
	                     size_t new_frame_size, int priority = 0);

	virtual void SetScope(detail::ScopePtr newscope);
	virtual detail::Scope* GetScope() const		{ return scope.get(); }

	const FuncTypePtr& GetType() const
		{ return type; }

	Kind GetKind() const	{ return kind; }

	const char* Name() const { return name.c_str(); }
	void SetName(const char* arg_name)	{ name = arg_name; }

	void Describe(ODesc* d) const override = 0;
	virtual void DescribeDebug(ODesc* d, const zeek::Args* args) const;

	virtual FuncPtr DoClone();

	virtual detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

	uint32_t GetUniqueFuncID() const { return unique_id; }
	static const FuncPtr& GetFuncPtrByID(uint32_t id)
		{ return id >= unique_ids.size() ? Func::nil : unique_ids[id]; }

protected:
	Func();

	// Copies this function's state into other.
	void CopyStateInto(Func* other) const;

	// Helper function for checking result of plugin hook.
	void CheckPluginResult(bool handled, const ValPtr& hook_result,
	                       FunctionFlavor flavor) const;

	std::vector<Body> bodies;
	detail::ScopePtr scope;
	Kind kind;
	uint32_t unique_id;
	FuncTypePtr type;
	std::string name;
	static inline std::vector<FuncPtr> unique_ids;
};

namespace detail {

class ScriptFunc final : public Func {
public:
	ScriptFunc(const IDPtr& id, StmtPtr body,
	        const std::vector<IDPtr>& inits,
	        size_t frame_size, int priority);

	~ScriptFunc() override;

	bool IsPure() const override;
	ValPtr Invoke(zeek::Args* args, Frame* parent) const override;

	/**
	 * Creates a separate frame for captures and initializes its
	 * elements.  The list of captures comes from the ScriptFunc's
	 * type, so doesn't need to be passed in, just the frame to
	 * use in evaluating the identifiers.
	 *
	 * @param f  the frame used for evaluating the captured identifiers
	 */
	void CreateCaptures(Frame* f);

	/**
	 * Returns the frame associated with this function for tracking
	 * captures, or nil if there isn't one.
	 *
	 * @return internal frame kept by the function for persisting captures
	 */
	Frame* GetCapturesFrame() const	{ return captures_frame; }

	// Same definition as in Frame.h.
	using OffsetMap = std::unordered_map<std::string, int>;

	/**
	 * Returns the mapping of captures to slots in the captures frame.
	 *
	 * @return pointer to mapping of captures to slots
	 */
	const OffsetMap* GetCapturesOffsetMap() const
		{ return captures_offset_mapping; }

	// The following "Closure" methods implement the deprecated
	// capture-by-reference functionality.

	/**
	 * Adds a closure to the function. Closures are cloned and
	 * future calls to ScriptFunc methods will not modify *f*.
	 *
	 * @param ids IDs that are captured by the closure.
	 * @param f the closure to be captured.
	 */
	void AddClosure(IDPList ids, Frame* f);

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
	 * Serializes this function's closure or capture frame.
	 *
	 * @return a serialized version of the function's closure/capture frame.
	 */
	broker::expected<broker::data> SerializeClosure() const;

	/**
	 * Sets the captures frame to one built from *data*.
	 *
	 * @param data a serialized frame
	 */
	bool DeserializeCaptures(const broker::vector& data);

	void AddBody(StmtPtr new_body,
	             const std::vector<IDPtr>& new_inits,
	             size_t new_frame_size, int priority) override;

	// Replace the given current instance of a function body with
	// a new one.
	void ReplaceBody(const detail::StmtPtr& old_body,
				detail::StmtPtr new_body);

	StmtPtr CurrentBody() const		{ return current_body; }

	/**
	 * Returns the function's frame size.
	 * @return  The number of ValPtr slots in the function's frame.
	 */
	int FrameSize() const			{ return frame_size; }

	/**
	 * Changes the function's frame size to a new size - used for
	 * script optimization/compilation.
	 *
	 * @param new_size  The frame size the function should use.
	 */
	void SetFrameSize(int new_size)		{ frame_size = new_size; }

	/** Sets this function's outer_id list. */
	void SetOuterIDs(IDPList ids)
		{ outer_ids = std::move(ids); }

	void Describe(ODesc* d) const override;

protected:
	ScriptFunc() : Func(SCRIPT_FUNC)	{}
	StmtPtr AddInits(
		StmtPtr body,
		const std::vector<IDPtr>& inits);

	/**
	 * Clones this function along with its closures.
	 */
	FuncPtr DoClone() override;

	/**
	 * Performs a selective clone of *f* using the IDs that were
	 * captured in the function's closure.
	 *
	 * @param f the frame to be cloned.
	 */
	void SetClosureFrame(Frame* f);

	/**
	 * Uses the given frame for captures, and generates the
	 * mapping from captured variables to offsets in the frame.
	 *
	 * @param f  the frame holding the values of capture variables
	 */
	void SetCaptures(Frame* f);

private:
	size_t frame_size;

	// List of the outer IDs used in the function.
	IDPList outer_ids;

	// The following is used for deprecated capture-by-reference
	// closures:
	// The frame the ScriptFunc was initialized in.
	Frame* closure = nullptr;
	bool weak_closure_ref = false;

	// Used for capture-by-copy closures.  These persist over the
	// function's lifetime, providing quasi-globals that maintain
	// state across individual calls to the function.
	Frame* captures_frame = nullptr;

	OffsetMap* captures_offset_mapping = nullptr;

	// The most recently added/updated body.
	StmtPtr current_body;
};

using built_in_func = BifReturnVal (*)(Frame* frame, const Args* args);

class BuiltinFunc final : public Func {
public:
	BuiltinFunc(built_in_func func, const char* name, bool is_pure);
	~BuiltinFunc() override;

	bool IsPure() const override;
	ValPtr Invoke(zeek::Args* args, Frame* parent) const override;
	built_in_func TheFunc() const	{ return func; }

	void Describe(ODesc* d) const override;

protected:
	BuiltinFunc()	{ func = nullptr; is_pure = 0; }

	built_in_func func;
	bool is_pure;
};

extern bool check_built_in_call(BuiltinFunc* f, CallExpr* call);

struct CallInfo {
	const CallExpr* call;
	const Func* func;
	const zeek::Args& args;
};

// Struct that collects all the specifics defining a Func. Used for ScriptFuncs
// with closures.
struct function_ingredients {

	// Gathers all of the information from a scope and a function body needed
	// to build a function.
	function_ingredients(ScopePtr scope, StmtPtr body);

	IDPtr id;
	StmtPtr body;
	std::vector<IDPtr> inits;
	int frame_size;
	int priority;
	ScopePtr scope;
};

extern std::vector<CallInfo> call_stack;

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;
extern std::vector<void (*)()> bif_initializers;
extern void init_primary_bifs();

inline void run_bif_initializers()
	{
	for ( const auto& bi : bif_initializers )
		bi();

	bif_initializers = {};
	}

extern void emit_builtin_exception(const char* msg);
extern void emit_builtin_exception(const char* msg, const ValPtr& arg);
extern void emit_builtin_exception(const char* msg, Obj* arg);

} // namespace detail

extern std::string render_call_stack();

// These methods are used by BIFs, so they're in the public namespace.
extern void emit_builtin_error(const char* msg);
extern void emit_builtin_error(const char* msg, const ValPtr&);
extern void emit_builtin_error(const char* msg, Obj* arg);

} // namespace zeek
