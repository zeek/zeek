// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/Inline.h"

#include "zeek/Desc.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/StmtOptInfo.h"

namespace zeek::detail
	{

constexpr int MAX_INLINE_SIZE = 1000;

void Inliner::Analyze()
	{
	// Locate self- and indirectly recursive functions.

	// Maps each function to any functions that it calls, either
	// directly or (ultimately) indirectly.
	std::unordered_map<const Func*, std::unordered_set<const Func*>> call_set;

	// Prime the call set for each function with the functions it
	// directly calls.
	for ( auto& f : funcs )
		{
		std::unordered_set<const Func*> cs;

		// Aspirational ....
		non_recursive_funcs.insert(f.Func());

		for ( auto& func : f.Profile()->ScriptCalls() )
			{
			cs.insert(func);

			if ( func == f.Func() )
				{
				if ( report_recursive )
					printf("%s is directly recursive\n", func->Name());

				non_recursive_funcs.erase(func);
				}
			}

		call_set[f.Func()] = cs;
		}

	// Transitive closure.  If we had any self-respect, we'd implement
	// Warshall's algorithm.  What we do here is feasible though since
	// Zeek call graphs tend not to be super-deep.  (We could also save
	// cycles by only analyzing non-[direct-or-indirect] leaves, as
	// was computed by the previous version of this code.  But in
	// practice, the execution time for this is completely dwarfed
	// by the expense of compiling inlined functions, so we keep it
	// simple.)

	// Whether a change has occurred.
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
						// We already have it.
						continue;

					addls.insert(ccc);

					if ( ccc != c.first )
						// Non-recursive.
						continue;

					if ( report_recursive )
						printf("%s is indirectly recursive, called by %s\n", c.first->Name(),
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

	for ( auto& f : funcs )
		{
		const auto& func_ptr = f.FuncPtr();
		const auto& func = func_ptr.get();
		const auto& body = f.Body();

		// Candidates are non-event, non-hook, non-recursive,
		// non-compiled functions ... that don't use lambdas or when's,
		// since we don't currently compute the closures/frame
		// sizes for them correctly, and more fundamentally since
		// we don't compile them and hence inlining them will
		// make the parent non-compilable.
		if ( should_analyze(func_ptr, body) && func->Flavor() == FUNC_FLAVOR_FUNCTION &&
		     non_recursive_funcs.count(func) > 0 && f.Profile()->NumLambdas() == 0 &&
		     f.Profile()->NumWhenStmts() == 0 && body->Tag() != STMT_CPP )
			inline_ables.insert(func);
		}

	for ( auto& f : funcs )
		if ( should_analyze(f.FuncPtr(), f.Body()) )
			InlineFunction(&f);
	}

void Inliner::InlineFunction(FuncInfo* f)
	{
	max_inlined_frame_size = 0;

	// It's important that we take the current frame size from the
	// *scope* and not f->Func().  The latter tracks the maximum required
	// across all bodies, but we want to track the size for this
	// particular body.
	curr_frame_size = f->Scope()->Length();

	auto oi = f->Body()->GetOptInfo();
	num_stmts = oi->num_stmts;
	num_exprs = oi->num_exprs;

	f->Body()->Inline(this);

	oi->num_stmts = num_stmts;
	oi->num_exprs = num_exprs;

	int new_frame_size = curr_frame_size + max_inlined_frame_size;

	if ( new_frame_size > f->Func()->FrameSize() )
		f->Func()->SetFrameSize(new_frame_size);
	}

ExprPtr Inliner::CheckForInlining(CallExprPtr c)
	{
	auto f = c->Func();

	if ( f->Tag() != EXPR_NAME )
		// We don't inline indirect calls.
		return c;

	auto n = f->AsNameExpr();
	auto func = n->Id();

	if ( ! func->IsGlobal() )
		return c;

	const auto& func_v = func->GetVal();
	if ( ! func_v )
		return c;

	auto function = func_v->AsFunc();

	if ( function->GetKind() != Func::SCRIPT_FUNC )
		return c;

	// Check for mismatches in argument count due to single-arg-of-type-any
	// loophole used for variadic BiFs.
	if ( function->GetType()->Params()->NumFields() == 1 && c->Args()->Exprs().size() != 1 )
		return c;

	auto func_vf = static_cast<ScriptFunc*>(function);

	if ( inline_ables.count(func_vf) == 0 )
		return c;

	// We're going to inline the body, unless it's too large.
	auto body = func_vf->GetBodies()[0].stmts; // there's only 1 body
	auto oi = body->GetOptInfo();

	if ( num_stmts + oi->num_stmts + num_exprs + oi->num_exprs > MAX_INLINE_SIZE )
		return nullptr;

	num_stmts += oi->num_stmts;
	num_exprs += oi->num_exprs;

	auto body_dup = body->Duplicate();
	body_dup->GetOptInfo()->num_stmts = oi->num_stmts;
	body_dup->GetOptInfo()->num_exprs = oi->num_exprs;

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
	auto& vars = scope->OrderedVars();
	int nparam = func_vf->GetType()->Params()->NumFields();

	std::vector<IDPtr> params;
	params.reserve(nparam);

	for ( int i = 0; i < nparam; ++i )
		params.emplace_back(vars[i]);

	// Recursively inline the body.  This is safe to do because we've
	// ensured there are no recursive loops ... but we have to be
	// careful in accounting for the frame sizes.
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

	ListExprPtr args = {NewRef{}, c->Args()};
	auto t = c->GetType();
	auto ie = make_intrusive<InlineExpr>(args, std::move(params), body_dup, curr_frame_size, t);
	ie->SetOriginal(c);

	return ie;
	}

	} // namespace zeek::detail
