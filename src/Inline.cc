// See the file "COPYING" in the main distribution directory for copyright.

#include "Inline.h"
#include "ScriptAnaly.h"
#include "ProfileFunc.h"


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
	std::unordered_set<Func*> inline_ables;

	while ( 1 )
		{
		++depth;

		new_ones.clear();

		for ( auto& c : candidates )
			if ( IsInlineAble(c, inline_ables) )
				{
				c->body->Inline(this);
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

	for ( auto& f : funcs )
		{
		// Only inline f if we didn't already do it.
		if ( inline_ables.find(f->func) == inline_ables.end() )
			f->body->Inline(this);
		}
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
	}

bool Inliner::IsInlineAble(FuncInfo* f, std::unordered_set<Func*>& inline_ables)
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
