// See the file "COPYING" in the main distribution directory for copyright.

#include "Inline.h"
#include "ScriptAnaly.h"
#include "ProfileFunc.h"
#include "Desc.h"


void Inliner::Analyze()
	{
	// We first recursively develop "leaves", i.e., simple
	// (non-event, non-hook) functions that don't call any
	// other script functions.  From the starting set of
	// true leaves we can then develop new leaves by in-lining
	// any functions that only call established leaves.  We
	// keep doing so until we don't find any more candidates.
	// At that point, every function that can be flattened to
	// only calling BiFs (or nothing) has been rewritten.  We
	// then go through the leftovers and do one round of inlining
	// on them (so they can take advantage of these leaves).

	// Initial candidates are non-event, non-hook functions.
	std::unordered_set<FuncInfo*> candidates;

	for ( auto& f : funcs )
		if ( f->func->Flavor() == FUNC_FLAVOR_FUNCTION )
			candidates.insert(f);

	int depth = 0;
	bool added_more = true;
	std::unordered_set<FuncInfo*> new_ones;	// to migrate to inline_ables

	while ( 1 )
		{
		++depth;

		new_ones.clear();

		for ( auto& c : candidates )
			if ( IsInlineAble(c) )
				{
				InlineFunction(c);
				new_ones.insert(c);
				}

		if ( new_ones.size() == 0 )
			break;

		for ( auto& n : new_ones )
			{
			candidates.erase(n);
			inline_ables.insert(n->func);
			}
		}

#if 0
	for ( auto& c : candidates )
		{
		printf("cannot inline %s:", c->func->Name());
		for ( auto& func : c->pf->script_calls )
			if ( inline_ables.find(func) == inline_ables.end() )
				printf(" %s", func->Name());

		printf("\n");
		}
#endif

#if 0
	for ( auto& f : funcs )
		{
		// Processing optimization: only spend time trying to inline f
		// if we didn't already do so.
		if ( inline_ables.find(f->func) == inline_ables.end() )
			InlineFunction(f);
		}
#endif
	}

void Inliner::InlineFunction(FuncInfo* f)
	{
	max_inlined_frame_size = 0;
	curr_frame_size = f->func->FrameSize();

	bool dump = false;	// streq(f->func->Name(), "test_func2");

	if ( dump )
		printf("%s body before inlining:\n%s\n", f->func->Name(), obj_desc(f->body));

	f->body->Inline(this);
	f->func->GrowFrameSize(max_inlined_frame_size);

	if ( dump )
		printf("%s body after inlining:\n%s\n", f->func->Name(), obj_desc(f->body));
	}

Expr* Inliner::CheckForInlining(CallExpr* c)
	{
	auto f = c->Func();

	if ( f->Tag() != EXPR_NAME )
		return c->Ref();

	auto n = f->AsNameExpr();
	auto func = n->Id();

	if ( ! func->IsGlobal() )
		return c->Ref();

	auto func_v = func->ID_Val();
	if ( ! func_v )
		return c->Ref();

	auto func_vf = func_v->AsFunc()->AsBroFunc();

	if ( ! func_vf )
		return c->Ref();

	if ( inline_ables.find(func_vf) == inline_ables.end() )
		return c->Ref();

	int frame_size = func_vf->FrameSize();
	if ( frame_size > max_inlined_frame_size )
		max_inlined_frame_size = frame_size;

	IntrusivePtr<ListExpr> args = {NewRef{}, c->Args()};
	auto body = func_vf->GetBodies()[0].stmts;
	auto t = c->Type();

	// Getting the names of the parameters is tricky.  It's tempting
	// to take them from the function's type declaration, but alas
	// Zeek allows forward-declaring a function with one set of parameter
	// names and then defining a later instance of it with different
	// names, as long as the types match.  So we have to glue together
	// the type declaration, which gives us the number of parameters,
	// with the scope, which gives us all the variables declared in
	// the function, *using the knowledge that the parameters are
	// declared first*.
	auto scope = func_vf->GetScope();
	auto vars = scope->OrderedVars();
	int nparam = func_vf->FType()->Args()->NumFields();

	auto params = new id_list;
	for ( int i = 0; i < nparam; ++i )
		params->append(vars[i].get());

	auto body_dup = body->Duplicate();
	return new InlineExpr(args, params, body_dup, curr_frame_size, t);
	}

bool Inliner::IsInlineAble(FuncInfo* f)
	{
	for ( auto& func : f->pf->script_calls )
		if ( inline_ables.find(func) == inline_ables.end() )
			// In principle we could allow calls to hooks
			// providing the hook is itself inline-able other
			// than the fact that it's a hook.  Not clear
			// that's enough of a gain to be worth the hassle.
			return false;

	return true;
	}
