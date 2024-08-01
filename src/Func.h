// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "zeek/Obj.h"
#include "zeek/Scope.h"
#include "zeek/Stmt.h"
#include "zeek/TraverseTypes.h"
#include "zeek/Type.h" /* for function_flavor */
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekList.h"

namespace zeek {

class Val;
class FuncType;
class BrokerData;
class BrokerListView;

namespace detail {

class Scope;
class Stmt;
class CallExpr;
class ID;
class Frame;
using ScopePtr = IntrusivePtr<Scope>;
using IDPtr = IntrusivePtr<ID>;
using StmtPtr = IntrusivePtr<Stmt>;

class ScriptFunc;
class FunctionIngredients;

} // namespace detail

class EventGroup;
using EventGroupPtr = std::shared_ptr<EventGroup>;

class Func;
using FuncPtr = IntrusivePtr<Func>;

class Func : public Obj {
public:
    static inline const FuncPtr nil;

    enum Kind { SCRIPT_FUNC, BUILTIN_FUNC };

    explicit Func(Kind arg_kind) : kind(arg_kind) {}

    virtual bool IsPure() const = 0;
    FunctionFlavor Flavor() const { return GetType()->Flavor(); }

    struct Body {
        detail::StmtPtr stmts;
        int priority;
        std::set<EventGroupPtr> groups;
        // If any of the groups are disabled, this body is disabled.
        // The disabled field is updated from EventGroup instances.
        bool disabled = false;

        bool operator<(const Body& other) const { return priority > other.priority; } // reverse sort
    };

    const std::vector<Body>& GetBodies() const { return bodies; }
    bool HasBodies() const { return ! bodies.empty(); }

    /**
     * Are there bodies and is any one of them enabled?
     *
     * @return  true if bodies exist and at least one is enabled.
     */
    bool HasEnabledBodies() const { return ! bodies.empty() && has_enabled_bodies; };

    /**
     * Is every body enabled?
     *
     * @return  true if all bodies are enabled. (If no bodies, then true.)
     */
    bool HasAllBodiesEnabled() const { return all_bodies_enabled; };

    /**
     * Calls a Zeek function.
     * @param args  the list of arguments to the function call.
     * @param parent  the frame from which the function is being called.
     * @return  the return value of the function call.
     */
    virtual ValPtr Invoke(zeek::Args* args, detail::Frame* parent = nullptr) const = 0;

    /**
     * A version of Invoke() taking a variable number of individual arguments.
     */
    template<class... Args>
    std::enable_if_t<std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>, ValPtr> Invoke(
        Args&&... args) const {
        auto zargs = zeek::Args{std::forward<Args>(args)...};
        return Invoke(&zargs);
    }

    // Various ways to add a new event handler to an existing function
    // (event).  The usual version to use is the first with its default
    // parameter.  All of the others are for use by script optimization,
    // as is a non-default second parameter to the first method, which
    // overrides the function body in "ingr".
    void AddBody(const detail::FunctionIngredients& ingr, detail::StmtPtr new_body = nullptr);
    virtual void AddBody(detail::StmtPtr new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size,
                         int priority, const std::set<EventGroupPtr>& groups);
    void AddBody(detail::StmtPtr new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size,
                 int priority = 0);
    void AddBody(detail::StmtPtr new_body, size_t new_frame_size);
    void AddBody(std::function<void(const zeek::Args&, detail::StmtFlowType&)> body, int priority = 0);

    virtual void SetScope(detail::ScopePtr newscope);
    virtual detail::ScopePtr GetScope() const { return scope; }

    const FuncTypePtr& GetType() const { return type; }

    Kind GetKind() const { return kind; }

    const char* Name() const { return name.c_str(); }
    const std::string& GetName() const { return name; }
    void SetName(const char* arg_name) { name = arg_name; }

    void Describe(ODesc* d) const override = 0;
    virtual void DescribeDebug(ODesc* d, const zeek::Args* args) const;

    virtual FuncPtr DoClone();

    virtual detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

protected:
    Func() = default;

    // Copies this function's state into other.
    void CopyStateInto(Func* other) const;

    // Helper function for checking result of plugin hook.
    void CheckPluginResult(bool handled, const ValPtr& hook_result, FunctionFlavor flavor) const;

    std::vector<Body> bodies;
    detail::ScopePtr scope;
    Kind kind = SCRIPT_FUNC;
    FuncTypePtr type;
    std::string name;

private:
    // EventGroup updates Func::Body.disabled and has_enabled_bodies.
    // This is friend/private with EventGroup here so that we do not
    // expose accessors in the zeek:: public interface.
    friend class EventGroup;
    bool has_enabled_bodies = true;
    bool all_bodies_enabled = true;
};

namespace detail {

class ScriptFunc : public Func {
public:
    ScriptFunc(const IDPtr& id);

    // For compiled scripts.
    ScriptFunc(std::string name, FuncTypePtr ft, std::vector<StmtPtr> bodies, std::vector<int> priorities);

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
     * Uses the given set of ZVal's for captures.  Note that this is
     * different from the method above, which uses its argument to
     * compute the captures, rather than here where they are pre-computed.
     *
     * Makes deep copies if required.
     *
     * @param cvec  a vector of ZVal's corresponding to the captures.
     */
    void CreateCaptures(std::unique_ptr<std::vector<ZVal>> cvec);

    /**
     * Returns the frame associated with this function for tracking
     * captures, or nil if there isn't one.
     *
     * @return internal frame kept by the function for persisting captures
     */
    Frame* GetCapturesFrame() const { return captures_frame; }

    /**
     * Returns the set of ZVal's used for captures.  It's okay to modify
     * these as long as memory-management is done for managed entries.
     *
     * @return internal vector of ZVal's kept for persisting captures
     */
    auto& GetCapturesVec() const {
        ASSERT(captures_vec);
        return *captures_vec;
    }

    // Same definition as in Frame.h.
    using OffsetMap = std::unordered_map<std::string, int>;

    /**
     * Returns the mapping of captures to slots in the captures frame.
     *
     * @return pointer to mapping of captures to slots
     */
    const OffsetMap* GetCapturesOffsetMap() const { return captures_offset_mapping; }

    /**
     * Serializes this function's capture frame.
     *
     * @return a serialized version of the function's capture frame.
     */
    virtual std::optional<BrokerData> SerializeCaptures() const;

    /**
     * Sets the captures frame to one built from *data*.
     *
     * @param data a serialized frame
     */
    bool DeserializeCaptures(BrokerListView data);

    using Func::AddBody;

    void AddBody(detail::StmtPtr new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size,
                 int priority, const std::set<EventGroupPtr>& groups) override;

    /**
     * Replaces the given current instance of a function body with
     * a new one.  If new_body is nil then the current instance is
     * deleted with no replacement.
     *
     * @param old_body  Body to replace.
     * @param new_body  New body to use; can be nil.
     */
    void ReplaceBody(const detail::StmtPtr& old_body, detail::StmtPtr new_body);

    StmtPtr CurrentBody() const { return current_body; }
    int CurrentPriority() const { return current_priority; }

    /**
     * Returns the function's frame size.
     * @return  The number of ValPtr slots in the function's frame.
     */
    int FrameSize() const { return frame_size; }

    /**
     * Changes the function's frame size to a new size - used for
     * script optimization/compilation.
     *
     * @param new_size  The frame size the function should use.
     */
    void SetFrameSize(int new_size) { frame_size = new_size; }

    /** Sets this function's outer_id list. */
    void SetOuterIDs(IDPList ids) { outer_ids = std::move(ids); }

    void Describe(ODesc* d) const override;

protected:
    ScriptFunc() : Func(SCRIPT_FUNC) {}

    StmtPtr AddInits(StmtPtr body, const std::vector<IDPtr>& inits);

    /**
     * Clones this function along with its captures.
     */
    FuncPtr DoClone() override;

    /**
     * Uses the given frame for captures, and generates the
     * mapping from captured variables to offsets in the frame.
     * Virtual so it can be modified for script optimization uses.
     *
     * @param f  the frame holding the values of capture variables
     */
    virtual void SetCaptures(Frame* f);

private:
    size_t frame_size = 0;

    // List of the outer IDs used in the function.
    IDPList outer_ids;

    // Frame for (capture-by-copy) closures.  These persist over the
    // function's lifetime, providing quasi-globals that maintain
    // state across individual calls to the function.
    Frame* captures_frame = nullptr;

    OffsetMap* captures_offset_mapping = nullptr;

    // Captures when using ZVal block instead of a Frame.
    std::unique_ptr<std::vector<ZVal>> captures_vec;

    // The most recently added/updated body ...
    StmtPtr current_body;

    // ... and its priority.
    int current_priority = 0;
};

using built_in_func = ValPtr (*)(Frame* frame, const Args* args);

class BuiltinFunc final : public Func {
public:
    BuiltinFunc(built_in_func func, const char* name, bool is_pure);
    ~BuiltinFunc() override = default;

    bool IsPure() const override;
    ValPtr Invoke(zeek::Args* args, Frame* parent) const override;
    built_in_func TheFunc() const { return func; }

    void Describe(ODesc* d) const override;

protected:
    BuiltinFunc() {
        func = nullptr;
        is_pure = 0;
    }

    built_in_func func;
    bool is_pure;
};

extern bool check_built_in_call(BuiltinFunc* f, CallExpr* call);

struct CallInfo {
    const CallExpr* call;
    const Func* func;
    const zeek::Args& args;
};

// Class that collects all the specifics defining a Func.
class FunctionIngredients {
public:
    // Gathers all of the information from a scope and a function body needed
    // to build a function.
    FunctionIngredients(ScopePtr scope, StmtPtr body, const std::string& module_name);

    const IDPtr& GetID() const { return id; }

    const StmtPtr& Body() const { return body; }
    void ReplaceBody(StmtPtr new_body) { body = std::move(new_body); }

    const auto& Inits() const { return inits; }
    void ClearInits() { inits.clear(); }

    size_t FrameSize() const { return frame_size; }
    int Priority() const { return priority; }
    const ScopePtr& Scope() const { return scope; }
    const auto& Groups() const { return groups; }

    // Used by script optimization to update lambda ingredients
    // after compilation.
    void SetFrameSize(size_t _frame_size) { frame_size = _frame_size; }

private:
    IDPtr id;
    StmtPtr body;
    std::vector<IDPtr> inits;
    size_t frame_size = 0;
    int priority = 0;
    ScopePtr scope;
    std::set<EventGroupPtr> groups;
};

using FunctionIngredientsPtr = std::shared_ptr<FunctionIngredients>;

extern std::vector<CallInfo> call_stack;

/**
 * Create a single BacktraceElement record val.
 *
 * @param name the name of the function.
 * @param args call argument vector created by MakeCallArgumentVector().
 * @param loc optional location information of the caller.
 *
 * @return record value representing a BacktraceElement.
 */
zeek::RecordValPtr make_backtrace_element(std::string_view name, const VectorValPtr args,
                                          const zeek::detail::Location* loc);

/**
 * Create a Zeek script Backtrace of the current script call_stack.
 *
 * @return VectorValPtr containing BacktraceElement entries.
 */
zeek::VectorValPtr get_current_script_backtrace();

// This is set to true after the built-in functions have been initialized.
extern bool did_builtin_init;
extern std::vector<void (*)()> bif_initializers;
extern void init_primary_bifs();

inline void run_bif_initializers() {
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
