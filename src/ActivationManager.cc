#include "zeek/Desc.h"
#include "zeek/ActivationManager.h"

using namespace std;

namespace zeek::detail
	{

Activation::Activation(ExprPtr _cond, bool _is_activated, bool _parent_activated, int _cond_depth)
	{
	cond = std::move(_cond);
	is_activated = _is_activated;
	parent_activated = _parent_activated;
	cond_depth = _cond_depth;
	}

Activation::~Activation()
	{
	ResetGlobals();
	}

void Activation::ResetGlobals()
	{
	if ( ! is_activated )
		{
		for ( auto& gv : global_vals )
			gv->SetVal(nullptr);

		auto gs = global_scope();

		for ( auto& gid : global_IDs )
			gs->RemoveGlobal(gid->Name(), gid);
		}

	global_vals.clear();
	global_IDs.clear();
	}

void ActivationManager::Start(ExprPtr cond, bool activate, int cond_depth)
	{
	activate = activate && IsActivated();

	auto a = std::make_unique<Activation>(cond, activate, IsActivated(), cond_depth);
	activation_stack.push_back(std::move(a));
	}

	} // namespace zeek::detail
