// See the file "COPYING" in the main distribution directory for copyright.

#include "Inline.h"
#include "ScriptAnaly.h"
#include "ProfileFunc.h"
#include "Desc.h"


void Inliner::Analyze()
	{
	// Locate self- and indirectly recursive functions.
	std::unordered_map<const Func*, std::unordered_set<const Func*>> call_set;

	// Prime the call set for each function with the functions it
	// directly calls.
	for ( auto& f : funcs )
		{
		std::unordered_set<const Func*> cs;

		// Aspirational ....
		non_recursive_funcs.insert(f->func);

		for ( auto& func : f->pf->script_calls )
			{
			cs.insert(func);

			if ( func == f->func )
				{
				if ( analysis_options.report_recursive )
					printf("%s is directly recursive\n",
						func->Name());

				non_recursive_funcs.erase(func);
				}
			}

		call_set[f->func] = cs;
		}

	// Transitive closure.  If we had any self-respect, we'd implement
	// Warshall's algorithm.  What we do here is feasible though since
	// Zeek call graphs tend not to be super-deep.  (We could also save
	// cycles by only analyzing non-[direct-or-indirect] leaves, as
	// was computed by the previous version of this code.  But in
	// practice, the execution time for this is completely dwarfed
	// by the expense of compiling inlined functions, so we keep it
	// simple.)
	bool did_addition = true;
	while ( did_addition )
		{
		did_addition = false;

		// Loop over all the functions of interest.
		for ( auto& c : call_set )
			{
			// For each of them, loop over the set of functions
			// they call.

			std::unordered_set<const Func*> addls;

			for ( auto& cc : c.second )
				{
				if ( cc == c.first )
					// Don't loop over ourselves.
					continue;

				// For each called function, pull up *its*
				// set of called functions.
				for ( auto& ccc : call_set[cc] )
					{
					// For each of those, if we don't
					// already have it, add it.
					if ( c.second.count(ccc) > 0 )
						// We have it.
						continue;

					addls.insert(ccc);

					if ( ccc != c.first )
						// Non-recursive.
						continue;

					if ( analysis_options.report_recursive )
						printf("%s is indirectly recursive, called by %s\n",
							c.first->Name(),
							cc->Name());

					non_recursive_funcs.erase(c.first);
					non_recursive_funcs.erase(cc);
					}
				}

			if ( addls.size() > 0 )
				{
				did_addition = true;

				for ( auto& a : addls )
					c.second.insert(a);
				}
			}
		}

	std::unordered_set<FuncInfo*> candidates;

	for ( auto& f : funcs )
		// Candidates are non-event, non-hook, non-recursive
		// functions ... that don't use lambdas, since we don't
		// currently compute the closures for them correctly.
		if ( f->func->Flavor() == FUNC_FLAVOR_FUNCTION &&
		     non_recursive_funcs.count(f->func) > 0 &&
		     f->pf->num_lambdas == 0 )
			inline_ables.insert(f->func);

	for ( auto& f : funcs )
		{
		// Processing optimization: only spend time trying to inline f
		// if we haven't marked it as inlineable.  This trades off a
		// bunch of compilation load (inlining every single function,
		// even though almost none will be called directly) for a
		// modest gain of having compiled code for those rare
		// circumstances in which a Zeek function can be called
		// not ultimately stemming from an event (such as global
		// scripting, or expiration functions).
		if ( inline_ables.count(f->func) == 0 )
			InlineFunction(f);
		}
	}

void Inliner::InlineFunction(FuncInfo* f)
	{
	max_inlined_frame_size = 0;

	// It's important that we take the current frame size from the
	// *scope* and not f->func.  The latter tracks the maximum required
	// across all bodies, but we want to track the size for this
	// particular body.
	curr_frame_size = f->scope->Length();

	bool dump = false;

	if ( dump )
		printf("%s body before inlining:\n%s\n", f->func->Name(), obj_desc(f->body));

	f->body->Inline(this);

	int new_frame_size = curr_frame_size + max_inlined_frame_size;

	if ( new_frame_size > f->func->FrameSize() )
		f->func->SetFrameSize(new_frame_size);

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

	if ( inline_ables.count(func_vf) == 0 )
		return c->Ref();

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

	// Recursively inline the body - necessary now that we no longer
	// build up in-lines from leaves.  This is safe to do because
	// we've ensured there are no recursive loops ...
	// ... but we have to be careful in accounting for the frame
	// sizes.
	int frame_size = func_vf->FrameSize();

	int hold_curr_frame_size = curr_frame_size;
	curr_frame_size = frame_size;

	int hold_max_inlined_frame_size = max_inlined_frame_size;
	max_inlined_frame_size = 0;

	body_dup->Inline(this);

	curr_frame_size = hold_curr_frame_size;

	int new_frame_size = frame_size + max_inlined_frame_size;

	if ( new_frame_size > hold_max_inlined_frame_size )
		max_inlined_frame_size = new_frame_size;
	else
		max_inlined_frame_size = hold_max_inlined_frame_size;

	auto ie = new InlineExpr(args, params, body_dup, curr_frame_size, t);
	ie->SetOriginal(c);

	return ie;
	}
