// See the file "COPYING" in the main distribution directory for copyright.

// Classes for supporting @activate-if constructs.

#pragma once

#include "zeek/Expr.h"
#include "zeek/Func.h"

namespace zeek::detail
	{

using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;
using AttrVec = std::unique_ptr<std::vector<AttrPtr>>;

class ActivationManager;

/**
 * The different types of ActivationEvent's.
 */
enum ActivationEventType
	{
	// Represents an @activate-if conditional, with a corresponding
	// condition expression, and sub-events (i.e., other ActivationEvent's)
	// for what occurs in the "true" and "false" branches.
	AE_COND,

	// Represents the introduction of a new global identifier.
	AE_CREATE_GLOBAL,

	// Represents adding a value (in particular, a ScriptFunc) to
	// a particular global.
	AE_ADDING_GLOBAL_VAL,

	// Represents a global having its initialization value and/or
	// attributes redef'd.
	AE_REDEF,

	// Represents an event handler being redef'd (which discards its
	// current value).
	AE_HANDLER_REDEF,

	// Represents adding a body to a function/hook/event handler.
	AE_BODY,
	};

/**
 * Expresses an event (with one of the above types) occurring during an
 * @activate-if.  Events reflect what *could* have happened rather than
 * what *did* happen, so events will be present even for @activate-if blocks
 * that were skipped due to their condition evaluating to false.
 *
 * The current use for these events is to enable the CPP script compiler
 * to generate run-time execution of @activate-if conditionals.  To do that,
 * it needs a record of their associated effects.
 *
 * We use a "flat" class that encompasses all of the possibilities, rather
 * than subclassing on the different types.  This is because ActivationEvent's
 * are a record for *reading* rather than conducting further processing
 * directly; hence there aren't apt active methods to virtualize.  If we
 * used subclasses, we'd wind up having to cast to get to the specifics
 * elements of a given event, which is clunky enough that it's not clear
 * we gain anything useful.
 */
class ActivationEvent
	{
public:
	// ActivationEvent's always have a type.  All the other fields
	// are optional, and are populated depending on the type.
	ActivationEvent(ActivationEventType _et) : et(_et) { }

	// Type of the activation event.
	ActivationEventType Type() const { return et; }

	// An associated expression associated.
	void AddExpr(ExprPtr _expr) { expr = std::move(_expr); }
	ExprPtr GetExpr() const { return expr; }

	// An associated identifier.
	void AddID(IDPtr _id) { id = std::move(_id); }
	IDPtr GetID() const { return id; }

	// An associated initialization class (equivalent to =/+=/-=).
	void AddInitClass(InitClass _c) { c = _c; }
	InitClass GetInitClass() const { return c; }

	// A set of associated attributes, or none if a nil pointer.
	void AddAttrs(AttrVec& _attrs)
		{
		// It's a pity that the code base has settled on unique_ptr's
		// for collections of attributes rather than shared_ptr's ...
		if ( _attrs )
			{
			attrs = std::make_unique<std::vector<AttrPtr>>();
			*attrs = *_attrs;
			}
		}
	const auto& GetAttrs() const { return attrs; }

	// A set of associated "ingredients" for building a function.
	void AddIngredients(std::shared_ptr<FunctionIngredients> _ingr) { ingr = std::move(_ingr); }
	const auto& GetIngredients() const { return ingr; }

	// Adds a "subevent" to this event, only valid for events that are
	// themselves conditionals.  Note that the subevent might itself
	// be a (nested) conditional.
	void AddSubEvent(std::shared_ptr<ActivationEvent> ae)
		{
		ASSERT(et == AE_COND);
		sub_events[sub_event_branch].push_back(std::move(ae));
		}

	// Changes this events accrural of subevents to correspond to its
	// "else" branch rather than its main/true branch.
	void SwitchToElse()
		{
		ASSERT(et == AE_COND);
		ASSERT(sub_event_branch == 0);
		++sub_event_branch;
		}

	// Prints out the event (and any subevents) for debug purposes.
	void Dump(int indent_level) const;

private:
	// Manages indentation when dumping events.
	void Indent(int indent_level) const;

	ActivationEventType et;
	ExprPtr expr;
	IDPtr id;
	InitClass c = INIT_NONE;
	AttrVec attrs;
	std::shared_ptr<FunctionIngredients> ingr;

	// For events corresponding to conditionals, we track two sets
	// of sub_events, one for the main (true) branch of the conditional,
	// and one for the else (false) branch, if any.  sub_event_branch
	// tracks which of these two we're adding to at the moment.
	int sub_event_branch = 0;
	std::vector<std::shared_ptr<ActivationEvent>> sub_events[2];
	};

/**
 * An "Activation" object tracks the status of a current @activate-if
 * conditional as it's being parsed.  Its role is to keep track of what's
 * up with the conditional for the live parsing, as opposed to what *could*
 * have happened (which is instead reflected in a set of ActivationEvent's).
 */
class Activation
	{
public:
	Activation(ExprPtr cond, bool _is_activated, bool _parent_activated, int _cond_depth);
	~Activation();

	// True if we're in the part of the @activiate-if conditional for
	// which we should be incorporating statements (making changes to
	// globals, adding function bodies, etc.).
	bool IsActivated() const { return is_activated; }

	// Returns the @if (not @activate-if) conditional depth associated
	// with this activation.  Used to tell whether a given @else or @endif
	// corresponds to this @activate-if, or something nested within it.
	int CondDepth() const { return cond_depth; }

	// Returns the ActivationEvent associated with this @activate-if.
	auto CondEvent() const { return cond_event; }

	// Tells the Activation to switch from its main (conditinal-is-true)
	// processing to its "else" (conditional-is-false) processing.
	void SwitchToElse()
		{
		// We're done tracking globals for the current body.
		ResetGlobals();

		// Toggle our activation status *unless* our parent (another
		// @activate-if) was itself not active, in which case we
		// stay inactive.
		if ( parent_activated )
			is_activated = ! is_activated;

		// Keep the ActivationEvent in synch.
		cond_event->SwitchToElse();
		}

	void AddGlobalID(IDPtr gid) { global_IDs.push_back(std::move(gid)); }
	void AddGlobalVal(IDPtr gid) { global_vals.push_back(std::move(gid)); }

private:
	// If we weren't active, then undo the effects that the parser had
	// to make (installing new globals and event handlers) in order
	// to assess the correctness of the code within the block.
	void ResetGlobals();

	std::shared_ptr<ActivationEvent> cond_event;

	// True if our parent was itself activated.  Always true if there
	// wasn't an outer @activate-if.
	bool parent_activated;

	// Whether we're currently activated.
	bool is_activated;

	// Depth of @if conditionals when this activation began.
	int cond_depth;

	// Set of globals that were added during processing of the current body.
	std::vector<IDPtr> global_IDs;

	// Similar: set of globals for which we added values.  We track
	// this only for function/hook/event handler bodies.
	std::vector<IDPtr> global_vals;
	};

/**
 * Class for managing the processing of @activate-if's.  Deals with
 * potential nesting, and with constructing a trace of the associated
 * ActivationEvents.
 */
class ActivationManager
	{
public:
	ActivationManager() = default;
	~ActivationManager();

	// True if we are currently inside an @activate-if.
	bool InsideConditional() const { return ! activation_stack.empty(); }

	// True if the current @activate-if corresponds to the given
	// @if conditional-depth.  Needed to disambiguate @else and @endif
	// tokens in the presence of possible inter-nesting of @if and
	// @activate-if constructs.
	bool InsideConditional(int cond_depth) const
		{
		if ( activation_stack.empty() )
			return false;

		return activation_stack.back()->CondDepth() == cond_depth;
		}

	// True if processing of the current script is "activated".  This
	// is the usual state of things, other than when inside the branch
	// of an @activate-if that doesn't correspond to its condition.
	bool IsActivated() const
		{
		return activation_stack.empty() || activation_stack.back()->IsActivated();
		}

	// Returns the nesting level of @activate-if's.  Used by the scanner
	// to find dangling conditionals at the end of files.  Typed as an
	// integer to match similar other structures in the scanner.
	int ActivationDepth() const { return static_cast<int>(activation_stack.size()); }

	// Tells the manager to being a new @activate-if conditional.
	// "cond" is the associated condition, "activate" reflects whether
	// the condition is true, and "cond_depth" is the depth of any
	// parent @if constructs.
	void Start(ExprPtr cond, bool activate, int cond_depth);

	// Tells the manager that an @else has been seen for its innermost
	// @activate-if.
	void SwitchToElse();

	// Tells the manager that an @endif has been seen for its innermost
	// @activate-if.
	void End();

	// Tells the manager that the parser is creating a new global
	// identifier.
	void CreatingGlobalID(IDPtr gid);

	// Tells the manager that the parser is adding a value to a global.
	void AddingGlobalVal(IDPtr gid);

	// Tells the manager that the parser is redef'ing an identifier using
	// the associated values.  Returns true if we're currently activated.
	bool AddingRedef(const IDPtr& id, InitClass c, ExprPtr init, AttrVec& attrs);

	// Tells the manger that the given identifier's event handler is
	// being redef'd.  Returns true if we're currently activated.
	bool RedefingHandler(const IDPtr& id);

	// Tells the manager that the parser is adding a function body to
	// the given function.  Returns true if we're currently activated.
	bool AddingBody(IDPtr func, std::shared_ptr<FunctionIngredients> ingr);

	// Returns a list of top-level ActivationEvent's.  These will all
	// be AE_COND events, which in general should be traversed recursively
	// to extract what happened inside the conditionals, including
	// additional conditionals potentially nested inside.
	const auto& ActivationEvents() const { return activation_events; }

private:
	// Currently live @activate-if information.
	std::vector<std::unique_ptr<Activation>> activation_stack;

	// A trace of all of the top-level @activate-if events.  Any
	// nested @activate-if's are available from the top-level events
	// as sub-events.
	std::vector<std::shared_ptr<ActivationEvent>> activation_events;
	};

extern ActivationManager* activation_mgr;

	} // namespace zeek::detail
