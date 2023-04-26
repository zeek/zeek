#pragma once

#include "zeek/Expr.h"
#include "zeek/Func.h"

namespace zeek::detail
	{

using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;
using AttrVec = std::unique_ptr<std::vector<AttrPtr>>;

class ActivationManager;

/**
 * XXX
 */
enum ActivationEventType
	{
	AE_COND,
	AE_CREATE_GLOBAL,
	AE_ADDING_GLOBAL_VAL,
	AE_REDEF,
	AE_HANDLER_REDEF,
	AE_BODY,
	};

class ActivationEvent
	{
public:
	ActivationEvent(ActivationEventType _et) : et(_et) { }

	ActivationEventType Type() const { return et; }

	void AddExpr(ExprPtr _expr) { expr = std::move(_expr); }
	ExprPtr GetExpr() const { return expr; }

	void AddID(IDPtr _id) { id = std::move(_id); }
	IDPtr GetID() const { return id; }

	void AddInitClass(InitClass _c) { c = _c; }
	InitClass GetInitClass() const { return c; }

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

	void AddIngredients(std::shared_ptr<FunctionIngredients> _ingr) { ingr = std::move(_ingr); }
	const auto& GetIngredients() const { return ingr; }

	void AddSubEvent(std::shared_ptr<ActivationEvent> ae)
		{
		sub_events[sub_event_branch].push_back(std::move(ae));
		}

	void SwitchToElse()
		{
		ASSERT(sub_event_branch == 0);
		++sub_event_branch;
		}

	void Dump(int indent_level) const;

private:
	void Indent(int indent_level) const;

	ActivationEventType et;
	ExprPtr expr;
	IDPtr id;
	InitClass c = INIT_NONE;
	AttrVec attrs;
	std::shared_ptr<FunctionIngredients> ingr;

	int sub_event_branch = 0;
	std::vector<std::shared_ptr<ActivationEvent>> sub_events[2];
	};

class Activation
	{
public:
	Activation(ExprPtr cond, bool _is_activated, bool _parent_activated, int _cond_depth);
	~Activation();

	auto CondEvent() const { return cond_event; }

	bool IsActivated() const { return is_activated; }
	int CondDepth() const { return cond_depth; }

	void SwitchToElse()
		{
		ResetGlobals();

		if ( parent_activated )
			is_activated = ! is_activated;

		cond_event->SwitchToElse();
		}

	void AddGlobalID(IDPtr gid) { global_IDs.push_back(std::move(gid)); }
	void AddGlobalVal(IDPtr gid) { global_vals.push_back(std::move(gid)); }

private:
	void ResetGlobals();

	std::shared_ptr<ActivationEvent> cond_event;

	bool parent_activated;
	bool is_activated;
	int cond_depth;

	std::vector<IDPtr> global_IDs;
	std::vector<IDPtr> global_vals;
	};

/**
 * XXX
 */
class ActivationManager
	{
public:
	ActivationManager() { }
	~ActivationManager();

	bool InsideConditional() const { return ! activation_stack.empty(); }
	bool InsideConditional(int cond_depth) const
		{
		if ( activation_stack.empty() )
			return false;

		return activation_stack.back()->CondDepth() == cond_depth;
		}

	bool IsActivated() const
		{
		return activation_stack.empty() || activation_stack.back()->IsActivated();
		}

	int ActivationDepth() const { return static_cast<int>(activation_stack.size()); }

	void Start(ExprPtr cond, bool activate, int cond_depth);
	void SwitchToElse();
	void End();

	void CreatingGlobalID(IDPtr gid);
	void AddingGlobalVal(IDPtr gid);

	bool AddingRedef(const IDPtr& id, InitClass c, ExprPtr init, AttrVec& attrs);
	bool RedefingHandler(const IDPtr& id);
	bool AddingBody(IDPtr func, std::shared_ptr<FunctionIngredients> ingr);

private:
	std::vector<std::unique_ptr<Activation>> activation_stack;
	std::vector<std::shared_ptr<ActivationEvent>> activation_events;
	};

extern std::unique_ptr<ActivationManager> activation_mgr;

	} // namespace zeek::detail
