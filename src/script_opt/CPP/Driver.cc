// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zeek/script_opt/CPP/Compile.h"


namespace zeek::detail {


CPPCompile::CPPCompile(std::vector<FuncInfo>& _funcs, ProfileFuncs& _pfs,
                       const char* gen_name, CPPHashManager& _hm,
                       bool _update, bool _standalone)
: funcs(_funcs), pfs(_pfs), hm(_hm), update(_update), standalone(_standalone)
	{
	auto mode = hm.IsAppend() ? "a" : "w";

	write_file = fopen(gen_name, mode);
	if ( ! write_file )
		{
		reporter->Error("can't open C++ target file %s", gen_name);
		exit(1);
		}

	if ( hm.IsAppend() )
		{
		// We need a unique number to associate with the name
		// space for the code we're adding.  A convenient way to
		// generate this safely is to use the present size of the
		// file we're appending to.  That guarantees that every
		// incremental compilation will wind up with a different
		// number.
		struct stat st;
		if ( fstat(fileno(write_file), &st) != 0 )
			{
			char buf[256];
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Error("fstat failed on %s: %s", gen_name, buf);
			exit(1);
			}

		// We use a value of "0" to mean "we're not appending,
		// we're generating from scratch", so make sure we're
		// distinct from that.
		addl_tag = st.st_size + 1;
		}

	Compile();
	}

CPPCompile::~CPPCompile()
	{
	fclose(write_file);
	}

void CPPCompile::Compile()
	{
	// Get the working directory so we can use it in diagnostic messages
	// as a way to identify this compilation.  Only germane when doing
	// incremental compilation (particularly of the test suite).
	char buf[8192];
	getcwd(buf, sizeof buf);
	working_dir = buf;

	if ( update && addl_tag > 0 && CheckForCollisions() )
		// Inconsistent compilation environment.
		exit(1);

	GenProlog();

	// Determine which functions we can call directly, and reuse
	// previously compiled instances of those if present.
	for ( const auto& func : funcs )
		{
		if ( func.Func()->Flavor() != FUNC_FLAVOR_FUNCTION )
			// Can't be called directly.
			continue;

		if ( IsCompilable(func) )
			compilable_funcs.insert(BodyName(func));

		auto h = func.Profile()->HashVal();
		if ( hm.HasHash(h) )
			{
			// Track the previously compiled instance
			// of this function.
			auto n = func.Func()->Name();
			hashed_funcs[n] = hm.FuncBodyName(h);
			}
		}

	// Track all of the types we'll be using.
	for ( const auto& t : pfs.RepTypes() )
		{
		TypePtr tp{NewRef{}, (Type*)(t)};
		types.AddKey(tp, pfs.HashType(t));
		}

	for ( const auto& t : types.DistinctKeys() )
		if ( ! types.IsInherited(t) )
			// Type is new to this compilation, so we'll
			// be generating it.
			Emit("TypePtr %s;", types.KeyName(t));

	NL();

	for ( const auto& c : pfs.Constants() )
		AddConstant(c);

	NL();

	for ( auto& g : pfs.AllGlobals() )
		CreateGlobal(g);

	// Now that the globals are created, register their attributes,
	// if any, and generate their initialization for use in standalone
	// scripts.  We can't do these in CreateGlobal() because at that
	// point it's possible that some of the globals refer to other
	// globals not-yet-created.
	for ( auto& g : pfs.AllGlobals() )
		{
		RegisterAttributes(g->GetAttrs());
		if ( g->HasVal() )
			{
			auto gn = std::string(g->Name());
			GenGlobalInit(g, globals[gn], g->GetVal());
			}
		}

	for ( const auto& e : pfs.Events() )
		if ( AddGlobal(e, "gl", false) )
			Emit("EventHandlerPtr %s_ev;", globals[std::string(e)]);

	for ( const auto& t : pfs.RepTypes() )
		{
		ASSERT(types.HasKey(t));
		TypePtr tp{NewRef{}, (Type*)(t)};
		RegisterType(tp);
		}

	// The scaffolding is now in place to go ahead and generate
	// the functions & lambdas.  First declare them ...
	for ( const auto& func : funcs )
		DeclareFunc(func);

	// We track lambdas by their internal names, because two different
	// LambdaExpr's can wind up referring to the same underlying lambda
	// if the bodies happen to be identical.  In that case, we don't
	// want to generate the lambda twice.
	std::unordered_set<std::string> lambda_names;
	for ( const auto& l : pfs.Lambdas() )
		{
		const auto& n = l->Name();
		if ( lambda_names.count(n) > 0 )
			// Skip it.
			continue;

		DeclareLambda(l, pfs.ExprProf(l).get());
		lambda_names.insert(n);
		}

	NL();

	// ... and now generate their bodies.
	for ( const auto& func : funcs )
		CompileFunc(func);

	lambda_names.clear();
	for ( const auto& l : pfs.Lambdas() )
		{
		const auto& n = l->Name();
		if ( lambda_names.count(n) > 0 )
			continue;

		CompileLambda(l, pfs.ExprProf(l).get());
		lambda_names.insert(n);
		}

	for ( const auto& f : compiled_funcs )
		RegisterCompiledBody(f);

	GenFuncVarInits();

	GenEpilog();
	}

void CPPCompile::GenProlog()
	{
	if ( addl_tag == 0 )
		{
		Emit("#include \"zeek/script_opt/CPP/Runtime.h\"\n");
		Emit("namespace zeek::detail { //\n");
		}

	Emit("namespace CPP_%s { // %s\n", Fmt(addl_tag), working_dir.c_str());

	// The following might-or-might-not wind up being populated/used.
	Emit("std::vector<int> field_mapping;");
	Emit("std::vector<int> enum_mapping;");
	NL();
	}

void CPPCompile::RegisterCompiledBody(const std::string& f)
	{
	auto h = body_hashes[f];
	auto p = body_priorities[f];

	// Build up an initializer of the events relevant to the function.
	std::string events;
	if ( body_events.count(f) > 0 )
		for ( auto e : body_events[f] )
			{
			if ( events.size() > 0 )
				events += ", ";
			events = events + "\"" + e + "\"";
			}

	events = std::string("{") + events + "}";

	if ( addl_tag > 0 )
		// Hash in the location associated with this compilation
		// pass, to get a final hash that avoids conflicts with
		// identical-but-in-a-different-context function bodies
		// when compiling potentially conflicting additional code
		// (which we want to support to enable quicker test suite
		// runs by enabling multiple tests to be compiled into the
		// same binary).
		h = merge_p_hashes(h, p_hash(cf_locs[f]));

	auto init = std::string("register_body__CPP(make_intrusive<") +
			f + "_cl>(\"" + f + "\"), " + Fmt(p) + ", " +
			Fmt(h) + ", " + events + ");";

	AddInit(names_to_bodies[f], init);

	if ( update )
		{
		fprintf(hm.HashFile(), "func\n%s%s\n",
		        scope_prefix(addl_tag).c_str(), f.c_str());
		fprintf(hm.HashFile(), "%llu\n", h);
		}
	}

void CPPCompile::GenEpilog()
	{
	NL();

	for ( const auto& e : init_exprs.DistinctKeys() )
		{
		GenInitExpr(e);
		if ( update )
			init_exprs.LogIfNew(e, addl_tag, hm.HashFile());
		}

	for ( const auto& a : attributes.DistinctKeys() )
		{
		GenAttrs(a);
		if ( update )
			attributes.LogIfNew(a, addl_tag, hm.HashFile());
		}

	// Generate the guts of compound types, and preserve type names
	// if present.
	for ( const auto& t : types.DistinctKeys() )
		{
		ExpandTypeVar(t);
		if ( update )
			types.LogIfNew(t, addl_tag, hm.HashFile());
		}

	InitializeEnumMappings();

	GenPreInits();

	std::unordered_set<const Obj*> to_do;
	for ( const auto& oi : obj_inits )
		to_do.insert(oi.first);

	CheckInitConsistency(to_do);
	auto nc = GenDependentInits(to_do);

	NL();
	Emit("void init__CPP()");

	StartBlock();

	Emit("enum_mapping.resize(%s);\n", Fmt(int(enum_names.size())));
	Emit("pre_init__CPP();");

	NL();
	for ( auto i = 1; i <= nc; ++i )
		Emit("init_%s__CPP();", Fmt(i));

	// Populate mappings for dynamic offsets.
	NL();
	InitializeFieldMappings();

	EndBlock(true);

	GenInitHook();

	Emit("} // %s\n\n", scope_prefix(addl_tag).c_str());

	if ( update )
		UpdateGlobalHashes();

	if ( addl_tag > 0 )
		return;

	Emit("#include \"zeek/script_opt/CPP/CPP-gen-addl.h\"\n");
	Emit("} // zeek::detail");
	}

bool CPPCompile::IsCompilable(const FuncInfo& func)
	{
	if ( func.ShouldSkip() )
		// Caller marked this function as one to skip.
		return false;

	if ( hm.HasHash(func.Profile()->HashVal()) )
		// We've already compiled it.
		return false;

	return is_CPP_compilable(func.Profile());
	}

} // zeek::detail
