// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
#include "GenRDs.h"
#include "Reduce.h"
#include "Inline.h"
#include "ZAM.h"
#include "Desc.h"
#include "EventRegistry.h"
#include "Reporter.h"


std::unordered_set<const Func*> non_recursive_funcs;



void optimize_func(BroFunc* f, IntrusivePtr<Scope> scope_ptr,
			IntrusivePtr<Stmt>& body)
	{
	if ( reporter->Errors() > 0 )
		return;

	if ( ! analysis_options.activate )
		return;

	if ( analysis_options.only_func &&
	     ! streq(f->Name(), analysis_options.only_func) )
		return;

	if ( analysis_options.only_func )
		printf("Original: %s\n", obj_desc(body));

	ProfileFunc pf_orig;
	body->Traverse(&pf_orig);

	if ( pf_orig.num_when_stmts > 0 || pf_orig.num_lambdas > 0 )
		{
		if ( analysis_options.only_func )
			printf("Skipping analysis due to \"when\" statement or use of lambdas\n");
		return;
		}

	auto scope = scope_ptr.get();

	::Ref(scope);
	push_existing_scope(scope);

	auto rc = new Reducer(scope);

	auto new_body = body->Reduce(rc);

	if ( reporter->Errors() > 0 )
		{
		pop_scope();
		delete rc;
		return;
		}

	non_reduced_perp = nullptr;
	checking_reduction = true;
	if ( ! new_body->IsReduced(rc) )
		printf("Reduction inconsistency for %s: %s\n", f->Name(),
			obj_desc(non_reduced_perp));
	checking_reduction = false;

	if ( analysis_options.only_func || analysis_options.dump_xform )
		printf("Transformed: %s\n", obj_desc(new_body));

	IntrusivePtr<Stmt> new_body_ptr = {AdoptRef{}, new_body};

	f->ReplaceBody(body, new_body_ptr);
	body = new_body_ptr;

	int new_frame_size =
		scope->Length() + rc->NumTemps() + rc->NumNewLocals();

	if ( new_frame_size > f->FrameSize() )
		f->SetFrameSize(new_frame_size);

	if ( analysis_options.optimize )
		{
		ProfileFunc pf_red;
		body->Traverse(&pf_red);

		auto cb = new RD_Decorate(&pf_red);
		cb->TraverseFunction(f, scope, new_body_ptr);

		if ( reporter->Errors() > 0 )
			{
			pop_scope();
			return;
			}

		rc->SetDefSetsMgr(cb->GetDefSetsMgr());
		rc->SetProfile(&pf_red);

		new_body = new_body->Reduce(rc);
		new_body_ptr = {AdoptRef{}, new_body};

		if ( analysis_options.only_func || analysis_options.dump_xform )
			printf("Optimized: %s\n", obj_desc(new_body));

		f->ReplaceBody(body, new_body_ptr);
		body = new_body_ptr;

		// See comment below about leaking cb.
		// delete cb;
		}

	ProfileFunc* pf_red = new ProfileFunc;
	body->Traverse(pf_red);

	auto cb = new RD_Decorate(pf_red);
	cb->TraverseFunction(f, scope, new_body_ptr);

	rc->SetDefSetsMgr(cb->GetDefSetsMgr());

	auto ud = new UseDefs(new_body, rc);
	ud->Analyze();

	if ( analysis_options.ud_dump )
		ud->Dump();

	ud->RemoveUnused();

	if ( analysis_options.compile )
		{
		auto zam = new ZAM(f, scope, new_body, ud, rc, pf_red);
		new_body = zam->CompileBody();

		if ( analysis_options.only_func || analysis_options.dump_code )
			zam->Dump();

		new_body_ptr = {AdoptRef{}, new_body};
		f->ReplaceBody(body, new_body_ptr);
		body = new_body_ptr;
		}

	delete ud;
	delete rc;
	delete pf_red;

	// We can actually speed up our analysis by 10+% by skipping this.
	// Clearly we need to revisit the data structures, but for now we
	// opt for expediency.
	// delete cb;

	pop_scope();
	}


FuncInfo::~FuncInfo()
	{
	delete pf;
	}

std::vector<FuncInfo*> funcs;

void analyze_func(BroFunc* f)
	{
	auto info = new FuncInfo(f, {NewRef{}, f->GetScope()}, f->CurrentBody());
	funcs.push_back(info);
	}

void analyze_orphan_functions()
	{
	std::unordered_set<Func*> called_functions;

	for ( auto& f : funcs )
		{
		for ( auto& c : f->pf->script_calls )
			called_functions.insert(c);

		// Functions can also be implicitly called, if they show
		// up in the globals of a function (which might be passing
		// the function to another function to call).

		for ( auto& g : f->pf->globals )
			if ( g->Type()->Tag() == TYPE_FUNC && g->ID_Val() &&
			     g->ID_Val()->AsFunc()->AsBroFunc() )
			called_functions.insert(g->ID_Val()->AsFunc());
		}

	for ( auto& f : funcs )
		{
		auto func = f->func;

		if ( func->Flavor() == FUNC_FLAVOR_FUNCTION )
			// Too many of these are unused to be worth reporting.
			continue;

		bool is_called =
			called_functions.find(func) != called_functions.end();

#if 0
		if ( ! is_called && func->Flavor() == FUNC_FLAVOR_FUNCTION )
			printf("orphan function %s\n", func->Name());
#endif

		if ( ! is_called && func->Flavor() == FUNC_FLAVOR_HOOK )
			printf("orphan hook %s\n", func->Name());
		}
	}

void analyze_orphan_events()
	{
	std::unordered_set<const char*> globals;

	for ( auto& f : funcs )
		for ( auto& g : f->pf->events )
			globals.insert(g);

	for ( auto& f : funcs )
		{
		auto func = f->func;

		if ( func->Flavor() == FUNC_FLAVOR_EVENT )
			{
			auto fn = func->Name();
			auto h = event_registry->Lookup(fn);
			if ( (! h || ! h->Used()) &&
			     globals.find(fn) == globals.end() )
				printf("event %s cannot be generated\n", fn);
			}
		}
	}


struct AnalyOpt analysis_options;

void analyze_scripts()
	{
	static bool did_init = false;

	if ( ! did_init )
		{
		if ( getenv("ZEEK_ANALY") )
			analysis_options.activate = true;

		analysis_options.only_func = getenv("ZEEK_ONLY");
		analysis_options.report_profile = getenv("ZEEK_ZAM_PROFILE");
		analysis_options.find_deep_uninits = getenv("ZEEK_FIND_DEEP_UNINITS");
		analysis_options.min_rd_trace = getenv("ZEEK_MIN_RD_TRACE");
		analysis_options.max_rd_trace = getenv("ZEEK_MAX_RD_TRACE");
		analysis_options.ud_dump = getenv("ZEEK_UD_DUMP");
		analysis_options.inliner = getenv("ZEEK_INLINE");
		analysis_options.optimize = getenv("ZEEK_OPTIMIZE");
		analysis_options.compile = getenv("ZEEK_COMPILE");
		analysis_options.no_ZAM_opt = getenv("ZEEK_NO_ZAM_OPT");
		analysis_options.dump_code = getenv("ZEEK_DUMP_CODE");
		analysis_options.dump_xform = getenv("ZEEK_DUMP_XFORM");

		if ( analysis_options.only_func )
			analysis_options.activate = true;

		did_init = true;
		}

	// Now that everything's parsed and BiF's have been initialized,
	// profile functions.
	for ( auto& f : funcs )
		{
		f->pf = new ProfileFunc();
		f->body->Traverse(f->pf);
		}

	// analyze_orphan_events();
	// analyze_orphan_functions();
	Inliner* inl = analysis_options.inliner ? new Inliner(funcs) : nullptr;

	for ( auto& f : funcs )
		{
		if ( inl && inl->WasInlined(f->func) )
			; // printf("skipping optimizing %s\n", f->func->Name());
		else
			{
#if 0
			auto loc = f->body->GetLocationInfo();
			printf("optimizing %s (%s line %d)\n", f->func->Name(),
				loc->filename ? loc->filename : "<none>",
				loc->first_line);
			// printf("body: %s\n", obj_desc(f->body));
#endif
			optimize_func(f->func, f->scope, f->body);
			}
		}

	finalize_functions(funcs);

	delete inl;
	}

void profile_script_execution()
	{
	// printf("%d vals created, %d destructed\n", num_Vals, num_del_Vals);
	// printf("%d string vals created, %d destructed\n", num_StringVals, num_del_StringVals);

	if ( analysis_options.report_profile )
		{
		report_ZOP_profile();

		for ( auto& f : funcs )
			{
			if ( f->body->Tag() == STMT_COMPILED )
				f->body->AsCompiler()->ProfileExecution();
			}
		}
	}

void finish_script_execution()
	{
	profile_script_execution();

	for ( auto& f : funcs )
		delete f;
	}
