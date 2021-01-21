// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
#include "GenRDs.h"
#include "Reduce.h"
#include "Inline.h"
#include "ZAM.h"
#include "input.h"
#include "Desc.h"
#include "EventRegistry.h"
#include "Reporter.h"


bool in_ZAM_file = false;

std::unordered_set<const Func*> non_recursive_funcs;


void optimize_func(BroFunc* f, ProfileFunc* pf,  IntrusivePtr<Scope> scope_ptr,
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

	if ( pf->num_when_stmts > 0 )
		{
		if ( analysis_options.only_func )
			printf("Skipping analysis due to \"when\" statement\n");
		return;
		}

	auto scope = scope_ptr.get();

	::Ref(scope);
	push_existing_scope(scope);

	auto rc = new Reducer(scope);
	auto new_body = rc->Reduce(body.get());

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

		new_body = rc->Reduce(new_body);

		if ( reporter->Errors() > 0 )
			{
			pop_scope();
			delete rc;
			return;
			}

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

		if ( reporter->Errors() > 0 )
			return;

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
	delete save_file;
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

		if ( func->Flavor() == FUNC_FLAVOR_EVENT )
			continue;

		if ( called_functions.find(func) != called_functions.end() )
			// It's called.
			continue;

		ODesc d;
		f->body->AddLocation(&d);
		printf("orphan %s %s (%s)\n",
			func->Flavor() == FUNC_FLAVOR_FUNCTION ?
				"function" : "hook",
			func->Name(), d.Description());
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
				{
				ODesc d;
				f->body->AddLocation(&d);
				printf("event %s cannot be generated (%s)\n",
					fn, d.Description());
				}
			}
		}
	}


struct AnalyOpt analysis_options;

static void check_env_opt(const char* opt, bool& opt_flag)
	{
	if ( getenv(opt) )
		opt_flag = true;
	}

void analyze_scripts()
	{
	static bool did_init = false;

	if ( ! did_init )
		{
		check_env_opt("ZEEK_ANALY", analysis_options.activate);
		check_env_opt("ZEEK_ZAM_PROFILE", analysis_options.report_profile);
		check_env_opt("ZEEK_MIN_RD_TRACE", analysis_options.min_rd_trace);
		check_env_opt("ZEEK_MAX_RD_TRACE", analysis_options.max_rd_trace);
		check_env_opt("ZEEK_UD_DUMP", analysis_options.ud_dump);
		check_env_opt("ZEEK_INLINE", analysis_options.inliner);
		check_env_opt("ZEEK_OPTIMIZE", analysis_options.optimize);
		check_env_opt("ZEEK_COMPILE", analysis_options.compile);
		check_env_opt("ZEEK_NO_ZAM_OPT", analysis_options.no_ZAM_opt);
		check_env_opt("ZEEK_DUMP_CODE", analysis_options.dump_code);
		check_env_opt("ZEEK_DUMP_XFORM", analysis_options.dump_xform);

		if ( getenv("ZEEK_USAGE_ISSUES") )
			analysis_options.usage_issues = 1;
		if ( getenv("ZEEK_DEEP_USAGE_ISSUES") )
			analysis_options.usage_issues = 2;

		if ( ! analysis_options.only_func )
			analysis_options.only_func = getenv("ZEEK_ONLY");

		if ( analysis_options.only_func )
			analysis_options.activate = true;

		did_init = true;
		}

	if ( ! analysis_options.activate && ! analysis_options.usage_issues &&
	     ! analysis_options.inliner )
		return;

	// Now that everything's parsed and BiF's have been initialized,
	// profile functions.
	std::unordered_map<const BroFunc*, const ProfileFunc*> func_profs;

	for ( auto& f : funcs )
		{
		f->pf = new ProfileFunc(true);
		f->body->Traverse(f->pf);
		func_profs[f->func] = f->pf;
		}

	// Figure out which functions either directly or indirectly
	// appear in "when" clauses.

	// Final set of functions involved in "when" clauses.
	std::unordered_set<const BroFunc*> when_funcs;

	// Which functions we need to analyze.
	std::unordered_set<const BroFunc*> when_funcs_to_do;

	for ( auto f : funcs )
		{
		if ( f->pf->when_calls.size() > 0 )
			{
			when_funcs.insert(f->func);

			for ( auto bf : f->pf->when_calls )
				when_funcs_to_do.insert(bf);

			if ( analysis_options.report_uncompilable )
				{
				ODesc d;
				f->func->AddLocation(&d);
				printf("%s cannot be compiled due to use of \"when\" statement (%s)\n",
					f->func->Name(), d.Description());
				}
			}
		}

	// Set of new functions to put on to-do list.  Separate from
	// the to-do list itself so we don't modify it while iterating
	// over it.
	std::unordered_set<const BroFunc*> new_to_do;

	while ( when_funcs_to_do.size() > 0 )
		{
		for ( auto wf : when_funcs_to_do )
			{
			when_funcs.insert(wf);

			for ( auto wff : func_profs[wf]->script_calls )
				{
				if ( when_funcs.count(wff) > 0 )
					// We've already processed this
					// function.
					continue;

				new_to_do.insert(wff);
				}
			}

		when_funcs_to_do = new_to_do;
		new_to_do.clear();
		}

	if ( analysis_options.report_orphans )
		{
		analyze_orphan_events();
		analyze_orphan_functions();
		}

	Inliner* inl = analysis_options.inliner ? new Inliner(funcs) : nullptr;

	if ( ! analysis_options.activate && ! analysis_options.usage_issues )
		{
		// We only got here due to wanting to inline, but not
		// wanting to otherwise analyze/transform.
		delete inl;
		return;
		}

	for ( auto& f : funcs )
		{
		if ( inl && inl->WasInlined(f->func) )
			// No need to compile as it won't be called directly.
			continue;

		if ( when_funcs.count(f->func) > 0 )
			// We don't try to compile these.
			continue;

		// Construct the associated compiled-ZAM filename.
		auto l = f->body->GetLocationInfo();

		if ( ! l->filename || streq(l->filename, "<stdin>") ||
		     analysis_options.usage_issues > 0 )
			{
			// Don't bother looking for prior compilation,
			// or creating such.
			optimize_func(f->func, f->pf, f->scope, f->body);
			continue;
			}

		char fn[8192];
		snprintf(fn, sizeof fn, "%s#%s:%d.%lx.ZAM", l->filename,
				f->func->Name(), l->first_line, f->pf->hash_val);

		bool did_load = false;

		auto save_file = fopen(fn, "r");
		if ( save_file )
			{
			if ( analysis_options.delete_save_files ||
			     analysis_options.overwrite_save_files )
				{
				fclose(save_file);
				if ( remove(fn) < 0 )
					{
					fprintf(stderr, "could not remove ZAM save file %s: %s\n",
						fn, strerror(errno));
					exit(1);
					}
				}

			else if ( analysis_options.no_load )
				fclose(save_file);

			else
				{
				scan_ZAM_file(fn, save_file);
				yyparse();
				fclose(save_file);

				f->func->ReplaceBody(f->body, ZAM_body);
				f->body = ZAM_body;

				did_load = true;
				}
			}

		if ( ! did_load )
			{
			if ( ! analysis_options.no_save &&
			     ! analysis_options.delete_save_files )
				f->save_file = copy_string(fn);

			optimize_func(f->func, f->pf, f->scope, f->body);
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
				f->body->AsZBody()->ProfileExecution();
			}
		}
	}

void finish_script_execution()
	{
	profile_script_execution();

	for ( auto& f : funcs )
		delete f;
	}
