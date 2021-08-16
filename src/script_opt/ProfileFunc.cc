// See the file "COPYING" in the main distribution directory for copyright.

#include <unistd.h>
#include <cerrno>

#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/Desc.h"
#include "zeek/Stmt.h"
#include "zeek/Func.h"


namespace zeek::detail {


// Computes the profiling hash of a Obj based on its (deterministic)
// description.
p_hash_type p_hash(const Obj* o)
	{
	ODesc d;
	d.SetDeterminism(true);
	o->Describe(&d);
	return p_hash(d.Description());
	}

std::string script_specific_filename(const StmtPtr& body)
	{
	// The specific filename is taken from the location filename, making
	// it absolute if necessary.
	auto body_loc = body->GetLocationInfo();
	auto bl_f = body_loc->filename;
	ASSERT(bl_f != nullptr);

	if ( (bl_f[0] != '.' && bl_f[0] != '/') ||
	     (bl_f[0] == '.' && (bl_f[1] == '/' ||
	                         (bl_f[1] == '.' && bl_f[2] == '/'))) )
		{
		// Add working directory to avoid collisions over the
		// same relative name.
		static std::string working_dir;
		if ( working_dir.empty() )
			{
			char buf[8192];
			if ( ! getcwd(buf, sizeof buf) )
				reporter->InternalError("getcwd failed: %s", strerror(errno));

			working_dir = buf;
			}

		return working_dir + "/" + bl_f;
		}

	return bl_f;
	}

p_hash_type script_specific_hash(const StmtPtr& body, p_hash_type generic_hash)
	{
	auto bl_f = script_specific_filename(body);
	return merge_p_hashes(generic_hash, p_hash(bl_f));
	}


ProfileFunc::ProfileFunc(const Func* func, const StmtPtr& body, bool _abs_rec_fields)
	{
	abs_rec_fields = _abs_rec_fields;
	Profile(func->GetType().get(), body);
	}

ProfileFunc::ProfileFunc(const Expr* e, bool _abs_rec_fields)
	{
	abs_rec_fields = _abs_rec_fields;

	if ( e->Tag() == EXPR_LAMBDA )
		{
		auto func = e->AsLambdaExpr();

		for ( auto oid : func->OuterIDs() )
			captures.insert(oid);

		Profile(func->GetType()->AsFuncType(), func->Ingredients().body);
		}

	else
		// We don't have a function type, so do the traversal
		// directly.
		e->Traverse(this);
	}

ProfileFunc::ProfileFunc(const Stmt* s, bool _abs_rec_fields)
	{
	abs_rec_fields = _abs_rec_fields;
	s->Traverse(this);
	}

void ProfileFunc::Profile(const FuncType* ft, const StmtPtr& body)
	{
	num_params = ft->Params()->NumFields();
	TrackType(ft);
	body->Traverse(this);
	}

TraversalCode ProfileFunc::PreStmt(const Stmt* s)
	{
	stmts.push_back(s);

	switch ( s->Tag() ) {
	case STMT_INIT:
		for ( const auto& id : s->AsInitStmt()->Inits() )
			{
			inits.insert(id.get());
			TrackType(id->GetType());
			}

		// Don't traverse further into the statement, since we
		// don't want to view the identifiers as locals unless
		// they're also used elsewhere.
		return TC_ABORTSTMT;

	case STMT_WHEN:
		++num_when_stmts;

		in_when = true;
		s->AsWhenStmt()->Cond()->Traverse(this);
		in_when = false;

		// It doesn't do any harm for us to re-traverse the
		// conditional, so we don't bother hand-traversing the
		// rest of the "when", but just let the usual processing
		// do it.
		break;

	case STMT_FOR:
		{
		auto sf = s->AsForStmt();
		auto loop_vars = sf->LoopVars();
		auto value_var = sf->ValueVar();

		for ( auto id : *loop_vars )
			locals.insert(id);

		if ( value_var )
			locals.insert(value_var.get());
		}
		break;

	case STMT_SWITCH:
		{
		// If this is a type-case switch statement, then find the
		// identifiers created so we can add them to our list of
		// locals.  Ideally this wouldn't be necessary since *surely*
		// if one bothers to define such an identifier then it'll be
		// subsequently used, and we'll pick up the local that way ...
		// but if for some reason it's not, then we would have an
		// incomplete list of locals that need to be tracked.

		auto sw = s->AsSwitchStmt();
		bool is_type_switch = false;

		for ( auto& c : *sw->Cases() )
			{
			auto idl = c->TypeCases();
			if ( idl )
				{
				for ( auto id : *idl )
					locals.insert(id);

				is_type_switch = true;
				}
			}

		if ( is_type_switch )
			type_switches.insert(sw);
		else
			expr_switches.insert(sw);
		}
		break;

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PreExpr(const Expr* e)
	{
	exprs.push_back(e);

	TrackType(e->GetType());

	switch ( e->Tag() ) {
	case EXPR_CONST:
		constants.push_back(e->AsConstExpr());
		break;

	case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();

		if ( id->IsGlobal() )
			{
			globals.insert(id);
			all_globals.insert(id);

			const auto& t = id->GetType();
			if ( t->Tag() == TYPE_FUNC &&
			     t->AsFuncType()->Flavor() == FUNC_FLAVOR_EVENT )
				events.insert(id->Name());
			}

		else
			{
			// This is a tad ugly.  Unfortunately due to the
			// weird way that Zeek function *declarations* work,
			// there's no reliable way to get the list of
			// parameters for a function *definition*, since
			// they can have different names than what's present
			// in the declaration.  So we identify them directly,
			// by knowing that they come at the beginning of the
			// frame ... and being careful to avoid misconfusing
			// a lambda capture with a low frame offset as a
			// parameter.
			if ( captures.count(id) == 0 &&
			     id->Offset() < num_params )
				params.insert(id);

			locals.insert(id);
			}

		// Turns out that NameExpr's can be constructed using a
		// different Type* than that of the identifier itself,
		// so be sure we track the latter too.
		TrackType(id->GetType());

		break;
		}

	case EXPR_FIELD:
		if ( abs_rec_fields )
			{
			auto f = e->AsFieldExpr()->Field();
			addl_hashes.push_back(p_hash(f));
			}
		else
			{
			auto fn = e->AsFieldExpr()->FieldName();
			addl_hashes.push_back(p_hash(fn));
			}
		break;

	case EXPR_HAS_FIELD:
		if ( abs_rec_fields )
			{
			auto f = e->AsHasFieldExpr()->Field();
			addl_hashes.push_back(std::hash<int>{}(f));
			}
		else
			{
			auto fn = e->AsHasFieldExpr()->FieldName();
			addl_hashes.push_back(std::hash<std::string>{}(fn));
			}
		break;

	case EXPR_INCR:
	case EXPR_DECR:
	case EXPR_ADD_TO:
	case EXPR_REMOVE_FROM:
	case EXPR_ASSIGN:
		{
		if ( e->GetOp1()->Tag() == EXPR_REF )
			{
			auto lhs = e->GetOp1()->GetOp1();
			if ( lhs->Tag() == EXPR_NAME )
				TrackAssignment(lhs->AsNameExpr()->Id());
			}
		// else this isn't a direct assignment.
		break;
		}

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();

		if ( f->Tag() != EXPR_NAME )
			{
			does_indirect_calls = true;
			return TC_CONTINUE;
			}

		auto n = f->AsNameExpr();
		auto func = n->Id();

		if ( ! func->IsGlobal() )
			{
			does_indirect_calls = true;
			return TC_CONTINUE;
			}

		all_globals.insert(func);

		auto func_v = func->GetVal();
		if ( func_v )
			{
			auto func_vf = func_v->AsFunc();

			if ( func_vf->GetKind() == Func::SCRIPT_FUNC )
				{
				auto bf = static_cast<ScriptFunc*>(func_vf);
				script_calls.insert(bf);

				if ( in_when )
					when_calls.insert(bf);
				}
			else
				BiF_globals.insert(func);
			}
		else
			{
			// We could complain, but for now we don't, because
			// if we're invoked prior to full Zeek initialization,
			// the value might indeed not there yet.
			// printf("no function value for global %s\n", func->Name());
			}

		// Recurse into the arguments.
		auto args = c->Args();
		args->Traverse(this);

		// Do the following explicitly, since we won't be recursing
		// into the LHS global.

		// Note that the type of the expression and the type of the
		// function can actually be *different* due to the NameExpr
		// being constructed based on a forward reference and then
		// the global getting a different (constructed) type when
		// the function is actually declared.  Geez.  So hedge our
		// bets.
		TrackType(n->GetType());
		TrackType(func->GetType());

		TrackID(func);

		return TC_ABORTSTMT;
		}

	case EXPR_EVENT:
		{
		auto ev = e->AsEventExpr()->Name();
		events.insert(ev);
		addl_hashes.push_back(p_hash(ev));
		}
		break;

	case EXPR_LAMBDA:
		{
		auto l = e->AsLambdaExpr();
		lambdas.push_back(l);

		for ( const auto& i : l->OuterIDs() )
			{
			locals.insert(i);
			TrackID(i);

			// See above re EXPR_NAME regarding the following
			// logic.
			if ( captures.count(i) == 0 &&
			     i->Offset() < num_params )
				params.insert(i);
			}

		// Avoid recursing into the body.
		return TC_ABORTSTMT;
		}

	case EXPR_SET_CONSTRUCTOR:
		{
		auto sc = static_cast<const SetConstructorExpr*>(e);
		const auto& attrs = sc->GetAttrs();

		if ( attrs )
			constructor_attrs.insert(attrs.get());
		}
		break;

	case EXPR_TABLE_CONSTRUCTOR:
		{
		auto tc = static_cast<const TableConstructorExpr*>(e);
		const auto& attrs = tc->GetAttrs();

		if ( attrs )
			constructor_attrs.insert(attrs.get());
		}
		break;

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PreID(const ID* id)
	{
	TrackID(id);

	// There's no need for any further analysis of this ID.
	return TC_ABORTSTMT;
	}

void ProfileFunc::TrackType(const Type* t)
	{
	if ( ! t )
		return;

	auto [it, inserted] = types.insert(t);

	if ( ! inserted )
		// We've already tracked it.
		return;

	ordered_types.push_back(t);
	}

void ProfileFunc::TrackID(const ID* id)
	{
	if ( ! id )
		return;

	auto [it, inserted] = ids.insert(id);

	if ( ! inserted )
		// Already tracked.
		return;

	ordered_ids.push_back(id);
	}

void ProfileFunc::TrackAssignment(const ID* id)
	{
	if ( assignees.count(id) > 0 )
		++assignees[id];
	else
		assignees[id] = 1;
	}


ProfileFuncs::ProfileFuncs(std::vector<FuncInfo>& funcs,
                           is_compilable_pred pred, bool _full_record_hashes)
	{
	full_record_hashes = _full_record_hashes;

	for ( auto& f : funcs )
		{
		if ( f.ShouldSkip() )
			continue;

		auto pf = std::make_unique<ProfileFunc>(f.Func(), f.Body(),
		                                        full_record_hashes);

		if ( ! pred || (*pred)(pf.get(), nullptr) )
			MergeInProfile(pf.get());
		else
			f.SetSkip(true);

		f.SetProfile(std::move(pf));
		func_profs[f.Func()] = f.ProfilePtr();
		}

	// We now have the main (starting) types used by all of the
	// functions.  Recursively compute their hashes.
	ComputeTypeHashes(main_types);

	// Computing the hashes can have marked expressions (seen in
	// record attributes) for further analysis.  Likewise, when
	// doing the profile merges above we may have noted lambda
	// expressions.  Analyze these, and iteratively any further
	// expressions that that analysis uncovers.
	DrainPendingExprs();

	// We now have all the information we need to form definitive,
	// deterministic hashes.
	ComputeBodyHashes(funcs);
	}

void ProfileFuncs::MergeInProfile(ProfileFunc* pf)
	{
	all_globals.insert(pf->AllGlobals().begin(), pf->AllGlobals().end());

	for ( auto& g : pf->Globals() )
		{
		auto [it, inserted] = globals.emplace(g);

		if ( ! inserted )
			continue;

		TraverseValue(g->GetVal());

		const auto& t = g->GetType();
		if ( t->Tag() == TYPE_TYPE )
			(void) HashType(t->AsTypeType()->GetType());

		auto& init_exprs = g->GetOptInfo()->GetInitExprs();
		for ( const auto& i_e : init_exprs )
			if ( i_e )
				{
				pending_exprs.push_back(i_e.get());

				if ( i_e->Tag() == EXPR_LAMBDA )
					lambdas.insert(i_e->AsLambdaExpr());
				}

		auto& attrs = g->GetAttrs();
		if ( attrs )
			AnalyzeAttrs(attrs.get());
		}

	constants.insert(pf->Constants().begin(), pf->Constants().end());
	main_types.insert(main_types.end(),
	                  pf->OrderedTypes().begin(), pf->OrderedTypes().end());
	script_calls.insert(pf->ScriptCalls().begin(), pf->ScriptCalls().end());
	BiF_globals.insert(pf->BiFGlobals().begin(), pf->BiFGlobals().end());
	events.insert(pf->Events().begin(), pf->Events().end());

	for ( auto& i : pf->Lambdas() )
		{
		lambdas.insert(i);
		pending_exprs.push_back(i);
		}

	for ( auto& a : pf->ConstructorAttrs() )
		AnalyzeAttrs(a);
	}

void ProfileFuncs::TraverseValue(const ValPtr& v)
	{
	if ( ! v )
		return;

	const auto& t = v->GetType();
	(void) HashType(t);

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ENUM:
	case TYPE_ERROR:
	case TYPE_FILE:
	case TYPE_FUNC:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_OPAQUE:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_SUBNET:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		break;

	case TYPE_RECORD:
		{
		auto r = cast_intrusive<RecordVal>(v);
		auto n = r->NumFields();

		for ( auto i = 0u; i < n; ++i )
			TraverseValue(r->GetField(i));
		}
		break;

	case TYPE_TABLE:
		{
		auto tv = cast_intrusive<TableVal>(v);
		auto tv_map = tv->ToMap();

		for ( auto& tv_i : tv_map )
			{
			TraverseValue(tv_i.first);
			TraverseValue(tv_i.second);
			}
		}
		break;

	case TYPE_LIST:
		{
		auto lv = cast_intrusive<ListVal>(v);
		auto n = lv->Length();

		for ( auto i = 0; i < n; ++i )
			TraverseValue(lv->Idx(i));
		}
		break;

	case TYPE_VECTOR:
		{
		auto vv = cast_intrusive<VectorVal>(v);
		auto n = vv->Size();

		for ( auto i = 0u; i < n; ++i )
			TraverseValue(vv->ValAt(i));
		}
		break;

	case TYPE_TYPE:
		(void) HashType(t->AsTypeType()->GetType());
		break;
	}
	}

void ProfileFuncs::DrainPendingExprs()
	{
	while ( pending_exprs.size() > 0 )
		{
		// Copy the pending expressions so we can loop over them
		// while accruing additions.
		auto pe = pending_exprs;
		pending_exprs.clear();

		for ( auto e : pe )
			{
			auto pf = std::make_shared<ProfileFunc>(e, full_record_hashes);

			expr_profs[e] = pf;
			MergeInProfile(pf.get());

			// It's important to compute the hashes over the
			// ordered types rather than the unordered.  If type
			// T1 depends on a recursive type T2, then T1's hash
			// will vary with depending on whether we arrive at
			// T1 via an in-progress traversal of T2 (in which
			// case T1 will see the "stub" in-progress hash for
			// T2), or via a separate type T3 (in which case it
			// will see the full hash).
			ComputeTypeHashes(pf->OrderedTypes());
			}
		}
	}

void ProfileFuncs::ComputeTypeHashes(const std::vector<const Type*>& types)
	{
	for ( auto t : types )
		(void) HashType(t);
	}

void ProfileFuncs::ComputeBodyHashes(std::vector<FuncInfo>& funcs)
	{
	for ( auto& f : funcs )
		if ( ! f.ShouldSkip() )
			ComputeProfileHash(f.ProfilePtr());

	for ( auto& l : lambdas )
		ComputeProfileHash(ExprProf(l));
	}

void ProfileFuncs::ComputeProfileHash(std::shared_ptr<ProfileFunc> pf)
	{
	p_hash_type h = 0;

	// We add markers between each class of hash component, to
	// prevent collisions due to elements with simple hashes
	// (such as Stmt's or Expr's that are only represented by
	// the hash of their tag).
	h = merge_p_hashes(h, p_hash("stmts"));
	for ( auto i : pf->Stmts() )
		h = merge_p_hashes(h, p_hash(i->Tag()));

	h = merge_p_hashes(h, p_hash("exprs"));
	for ( auto i : pf->Exprs() )
		h = merge_p_hashes(h, p_hash(i->Tag()));

	h = merge_p_hashes(h, p_hash("ids"));
	for ( auto i : pf->OrderedIdentifiers() )
		h = merge_p_hashes(h, p_hash(i->Name()));

	h = merge_p_hashes(h, p_hash("constants"));
	for ( auto i : pf->Constants() )
		h = merge_p_hashes(h, p_hash(i->Value()));

	h = merge_p_hashes(h, p_hash("types"));
	for ( auto i : pf->OrderedTypes() )
		h = merge_p_hashes(h, HashType(i));

	h = merge_p_hashes(h, p_hash("lambdas"));
	for ( auto i : pf->Lambdas() )
		h = merge_p_hashes(h, p_hash(i));

	h = merge_p_hashes(h, p_hash("addl"));
	for ( auto i : pf->AdditionalHashes() )
		h = merge_p_hashes(h, i);

	pf->SetHashVal(h);
	}

p_hash_type ProfileFuncs::HashType(const Type* t)
	{
	if ( ! t )
		return 0;

	auto it = type_hashes.find(t);

	if ( it != type_hashes.end() )
		// We've already done this Type*.
		return it->second;

	auto& tn = t->GetName();
	if ( ! tn.empty() )
		{
		auto seen_it = seen_type_names.find(tn);

		if ( seen_it != seen_type_names.end() )
			{
			// We've already done a type with the same name, even
			// though with a different Type*.  Reuse its results.
			auto seen_t = seen_it->second;
			auto h = type_hashes[seen_t];

			type_hashes[t] = h;
			type_to_rep[t] = type_to_rep[seen_t];

			return h;
			}
		}

	auto h = p_hash(t->Tag());
	if ( ! tn.empty() )
		h = merge_p_hashes(h, p_hash(tn));

	// Enter an initial value for this type's hash.  We'll update it
	// at the end, but having it here first will prevent recursive
	// records from leading to infinite recursion as we traverse them.
	// It's okay that the initial value is degenerate, because if we access
	// it during the traversal that will only happen due to a recursive
	// type, in which case the other elements of that type will serve
	// to differentiate its hash.
	type_hashes[t] = h;

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ENUM:
	case TYPE_ERROR:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_OPAQUE:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_SUBNET:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		h = merge_p_hashes(h, p_hash(t));
		break;

	case TYPE_RECORD:
		{
		const auto& ft = t->AsRecordType();
		auto n = ft->NumFields();
		auto orig_n = ft->NumOrigFields();

		h = merge_p_hashes(h, p_hash("record"));

		if ( full_record_hashes )
			h = merge_p_hashes(h, p_hash(n));
		else
			h = merge_p_hashes(h, p_hash(orig_n));

		for ( auto i = 0; i < n; ++i )
			{
			bool do_hash = full_record_hashes;
			if ( ! do_hash )
				do_hash = (i < orig_n);

			const auto& f = ft->FieldDecl(i);
			auto type_h = HashType(f->type);

			if ( do_hash )
				{
				h = merge_p_hashes(h, p_hash(f->id));
				h = merge_p_hashes(h, type_h);
				}

			h = merge_p_hashes(h, p_hash(f->id));
			h = merge_p_hashes(h, HashType(f->type));

			// We don't hash the field name, as in some contexts
			// those are ignored.

			if ( f->attrs )
				{
				if ( do_hash )
					h = merge_p_hashes(h, HashAttrs(f->attrs));
				AnalyzeAttrs(f->attrs.get());
				}
			}
		}
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();
		h = merge_p_hashes(h, p_hash("table"));
		h = merge_p_hashes(h, p_hash("indices"));
		h = merge_p_hashes(h, HashType(tbl->GetIndices()));
		h = merge_p_hashes(h, p_hash("tbl-yield"));
		h = merge_p_hashes(h, HashType(tbl->Yield()));
		}
		break;

	case TYPE_FUNC:
		{
		auto ft = t->AsFuncType();
		auto flv = ft->FlavorString();
		h = merge_p_hashes(h, p_hash(flv));
		h = merge_p_hashes(h, p_hash("params"));
		h = merge_p_hashes(h, HashType(ft->Params()));
		h = merge_p_hashes(h, p_hash("func-yield"));
		h = merge_p_hashes(h, HashType(ft->Yield()));
		}
		break;

	case TYPE_LIST:
		{
		auto& tl = t->AsTypeList()->GetTypes();

		h = merge_p_hashes(h, p_hash("list"));
		h = merge_p_hashes(h, p_hash(tl.size()));

		for ( const auto& tl_i : tl )
			h = merge_p_hashes(h, HashType(tl_i));
		}
		break;

	case TYPE_VECTOR:
		h = merge_p_hashes(h, p_hash("vec"));
		h = merge_p_hashes(h, HashType(t->AsVectorType()->Yield()));
		break;

	case TYPE_FILE:
		h = merge_p_hashes(h, p_hash("file"));
		h = merge_p_hashes(h, HashType(t->AsFileType()->Yield()));
		break;

	case TYPE_TYPE:
		h = merge_p_hashes(h, p_hash("type"));
		h = merge_p_hashes(h, HashType(t->AsTypeType()->GetType()));
		break;
	}

	type_hashes[t] = h;

	auto [rep_it, rep_inserted] = type_hash_reps.emplace(h, t);

	if ( rep_inserted )
		{ // No previous rep, so use this Type* for that.
		type_to_rep[t] = t;
		rep_types.push_back(t);
		}
	else
		type_to_rep[t] = rep_it->second;

	if ( ! tn.empty() )
		seen_type_names[tn] = t;

	return h;
	}

p_hash_type ProfileFuncs::HashAttrs(const AttributesPtr& Attrs)
	{
	// It's tempting to just use p_hash, but that won't work
	// if the attributes wind up with extensible records in their
	// descriptions, if we're not doing full record hashes.
	auto attrs = Attrs->GetAttrs();
	p_hash_type h = 0;

	for ( const auto& a : attrs )
		{
		h = merge_p_hashes(h, p_hash(a->Tag()));
		auto e = a->GetExpr();

		// We don't try to hash an associated expression, since those
		// can vary in structure due to compilation of elements.  We
		// do though enforce consistency for their types.
		if ( e )
			h = merge_p_hashes(h, HashType(e->GetType()));
		}

	return h;
	}

void ProfileFuncs::AnalyzeAttrs(const Attributes* Attrs)
	{
	auto attrs = Attrs->GetAttrs();

	for ( const auto& a : attrs )
		{
		const Expr* e = a->GetExpr().get();

		if ( e )
			{
			pending_exprs.push_back(e);
			if ( e->Tag() == EXPR_LAMBDA )
				lambdas.insert(e->AsLambdaExpr());
			}
		}
	}

} // namespace zeek::detail
