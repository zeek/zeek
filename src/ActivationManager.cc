#include "zeek/ActivationManager.h"

#include "zeek/Desc.h"

using namespace std;

namespace zeek::detail
	{

void ActivationEvent::Dump(int indent_level) const
	{
	Indent(indent_level);

	switch ( et )
		{
		case ActivationEvent::COND:
			printf("Cond");
			break;
		case ActivationEvent::CREATE_GLOBAL:
			printf("Create Global");
			break;
		case ActivationEvent::ADDING_GLOBAL_VAL:
			printf("Add Global Val");
			break;
		case ActivationEvent::REDEF:
			printf("Redef");
			break;
		case ActivationEvent::HANDLER_REDEF:
			printf("Handler Redef");
			break;
		case ActivationEvent::BODY:
			printf("Body");
			break;
		}

	if ( id )
		printf(" ID=%s", obj_desc(id.get()).c_str());

	if ( expr )
		printf(" expr=%s", obj_desc(expr.get()).c_str());

	printf("\n");

	if ( et != ActivationEvent::COND )
		return;

	Indent(indent_level);
	printf("TRUE:\n");
	for ( auto& s : T_sub_events )
		s->Dump(indent_level + 1);

	if ( ! in_true_branch )
		{
		Indent(indent_level);
		printf("FALSE:\n");
		for ( auto& s : F_sub_events )
			s->Dump(indent_level + 1);
		}

	Indent(indent_level);
	printf("END\n");
	}

void ActivationEvent::Indent(int indent_level) const
	{
	while ( indent_level-- > 0 )
		printf("\t");
	}

Activation::Activation(ExprPtr cond, bool _is_activated, bool _parent_activated, int _cond_depth)
	{
	is_activated = _is_activated;
	parent_activated = _parent_activated;
	cond_depth = _cond_depth;

	cond_event = std::make_shared<ActivationEvent>(ActivationEvent::COND);
	cond_event->AddExpr(cond);
	}

Activation::~Activation()
	{
	ResetGlobals();
	}

void Activation::ResetGlobals()
	{
	if ( ! is_activated )
		{ // undo changes we temporarily introduced
		for ( auto& gv : global_vals )
			gv->SetVal(nullptr);

		auto gs = global_scope();

		if ( gs )
			for ( auto& gid : global_IDs )
				gs->RemoveGlobal(gid->Name(), gid);
		}

	global_vals.clear();
	global_IDs.clear();
	}

ActivationManager::~ActivationManager()
	{
#if 0
	for ( auto& ae : activation_events )
		ae->Dump(0);
#endif
	}

void ActivationManager::Start(ExprPtr cond, bool activate, int cond_depth)
	{
	activate = activate && IsActivated();
	auto a = std::make_unique<Activation>(cond, activate, IsActivated(), cond_depth);

	auto ce = a->CondEvent();

	if ( activation_stack.empty() )
		activation_events.push_back(ce);
	else
		activation_stack.back()->CondEvent()->AddSubEvent(std::move(ce));

	activation_stack.push_back(std::move(a));
	}

void ActivationManager::SwitchToElse()
	{
	ASSERT(! activation_stack.empty());
	activation_stack.back()->SwitchToElse();
	}

void ActivationManager::End()
	{
	ASSERT(! activation_stack.empty());
	activation_stack.pop_back();
	}

void ActivationManager::CreatingGlobalID(IDPtr gid)
	{
	if ( activation_stack.empty() )
		return;

	auto cg = std::make_shared<ActivationEvent>(ActivationEvent::CREATE_GLOBAL);
	cg->AddID(gid);

	activation_stack.back()->CondEvent()->AddSubEvent(std::move(cg));
	activation_stack.back()->AddGlobalID(std::move(gid));
	}

void ActivationManager::AddingGlobalVal(IDPtr gid)
	{
	if ( activation_stack.empty() )
		return;

	auto gv = std::make_shared<ActivationEvent>(ActivationEvent::ADDING_GLOBAL_VAL);
	gv->AddID(gid);

	activation_stack.back()->CondEvent()->AddSubEvent(std::move(gv));
	activation_stack.back()->AddGlobalVal(std::move(gid));
	}

void ActivationManager::AddingRedef(const IDPtr& id, InitClass c, ExprPtr init, AttrVec& attrs)
	{
	if ( activation_stack.empty() )
		return;

	auto r = std::make_shared<ActivationEvent>(ActivationEvent::REDEF);
	r->AddID(id);
	r->AddInitClass(c);
	r->AddExpr(init);
	r->AddAttrs(attrs);

	activation_stack.back()->CondEvent()->AddSubEvent(std::move(r));
	}

void ActivationManager::RedefingHandler(const IDPtr& id)
	{
	if ( activation_stack.empty() )
		return;

	auto hr = std::make_shared<ActivationEvent>(ActivationEvent::HANDLER_REDEF);
	hr->AddID(id);

	activation_stack.back()->CondEvent()->AddSubEvent(std::move(hr));
	}

void ActivationManager::AddingBody(IDPtr func, std::shared_ptr<FunctionIngredients> ingr)
	{
	if ( activation_stack.empty() )
		return;

	auto b = std::make_shared<ActivationEvent>(ActivationEvent::BODY);
	b->AddID(func);
	b->AddIngredients(std::move(ingr));

	activation_stack.back()->CondEvent()->AddSubEvent(std::move(b));
	}

	} // namespace zeek::detail
