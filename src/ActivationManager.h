#pragma once

#include "zeek/Expr.h"

namespace zeek::detail
	{

class ActivationManager;

class Activation
	{
public:
	Activation(ExprPtr _cond, bool _is_activated, bool _parent_activated, int _cond_depth);
	~Activation();

	bool IsActivated() const { return is_activated; }
	int CondDepth() const { return cond_depth; }

	void SwitchToElse()
		{
		ResetGlobals();

		if ( parent_activated )
			is_activated = ! is_activated;
		}

	void AddGlobalID(IDPtr gid) { global_IDs.push_back(std::move(gid)); }
	void AddGlobalVal(IDPtr gv) { global_vals.push_back(std::move(gv)); }

private:
	void ResetGlobals();

	ExprPtr cond;
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
	ActivationManager() {}

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

	void Start(ExprPtr cond, bool activate, int cond_depth);

	void SwitchToElse()
		{
		ASSERT(! activation_stack.empty());
		activation_stack.back()->SwitchToElse();
		}

	void End()
		{
		activation_stack.pop_back();
		}

	void CreatingGlobalID(IDPtr gid)
		{
		if ( ! activation_stack.empty() )
			activation_stack.back()->AddGlobalID(std::move(gid));
		}

	void AddingGlobalVal(IDPtr gv)
		{
		if ( ! activation_stack.empty() )
			activation_stack.back()->AddGlobalVal(std::move(gv));
		}

private:
	std::vector<std::unique_ptr<Activation>> activation_stack;
	};

extern ActivationManager* activation_mgr;

	} // namespace zeek::detail
