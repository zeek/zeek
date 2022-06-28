// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>

#include "zeek/script_opt/CPP/Compile.h"

extern std::unordered_set<std::string> files_with_conditionals;

namespace zeek::detail
	{

using namespace std;

CPPCompile::CPPCompile(vector<FuncInfo>& _funcs, ProfileFuncs& _pfs, const string& gen_name,
                       bool add, bool _standalone, bool report_uncompilable)
	: funcs(_funcs), pfs(_pfs), standalone(_standalone)
	{
	auto target_name = gen_name.c_str();
	auto mode = add ? "a" : "w";

	write_file = fopen(target_name, mode);
	if ( ! write_file )
		{
		reporter->Error("can't open C++ target file %s", target_name);
		exit(1);
		}

	if ( add )
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
			reporter->Error("fstat failed on %s: %s", target_name, buf);
			exit(1);
			}

		// We use a value of "0" to mean "we're not appending,
		// we're generating from scratch", so make sure we're
		// distinct from that.
		addl_tag = st.st_size + 1;
		}

	else
		addl_tag = 0;

	Compile(report_uncompilable);
	}

CPPCompile::~CPPCompile()
	{
	fclose(write_file);
	}

void CPPCompile::Compile(bool report_uncompilable)
	{
	// Get the working directory so we can use it in diagnostic messages
	// as a way to identify this compilation.  Only germane when doing
	// incremental compilation (particularly of the test suite).
	char buf[8192];
	if ( ! getcwd(buf, sizeof buf) )
		reporter->FatalError("getcwd failed: %s", strerror(errno));

	working_dir = buf;

	GenProlog();

	unordered_set<string> filenames_reported_as_skipped;

	// Determine which functions we can call directly, and reuse
	// previously compiled instances of those if present.
	for ( auto& func : funcs )
		{
		const auto& f = func.Func();

		auto& ofiles = analysis_options.only_files;
		string fn = func.Body()->GetLocationInfo()->filename;

		if ( ! func.ShouldSkip() && ! ofiles.empty() && files_with_conditionals.count(fn) > 0 )
			{
			if ( filenames_reported_as_skipped.count(fn) == 0 )
				{
				reporter->Warning(
					"skipping compilation of files in %s due to presence of conditional code",
					fn.c_str());
				filenames_reported_as_skipped.insert(fn);
				}

			func.SetSkip(true);
			}

		if ( func.ShouldSkip() )
			{
			not_fully_compilable.insert(f->Name());
			continue;
			}

		const char* reason;
		if ( IsCompilable(func, &reason) )
			{
			if ( f->Flavor() == FUNC_FLAVOR_FUNCTION )
				// Note this as a callable compiled function.
				compilable_funcs.insert(BodyName(func));
			}
		else
			{
			if ( reason && standalone )
				reporter->Error("%s cannot be compiled to standalone C++ due to %s", f->Name(),
				                reason);

			else if ( reason && report_uncompilable )
				fprintf(stderr, "%s cannot be compiled to C++ due to %s\n", f->Name(), reason);

			not_fully_compilable.insert(f->Name());
			}
		}

	// Track all of the types we'll be using.
	for ( const auto& t : pfs.RepTypes() )
		{
		TypePtr tp{NewRef{}, (Type*)(t)};
		types.AddKey(tp, pfs.HashType(t));
		}

	Emit("TypePtr types__CPP[%s];", Fmt(static_cast<int>(types.DistinctKeys().size())));

	NL();

	for ( auto& g : pfs.AllGlobals() )
		CreateGlobal(g);

	for ( const auto& e : pfs.Events() )
		if ( AddGlobal(e, "gl") )
			Emit("EventHandlerPtr %s_ev;", globals[string(e)]);

	for ( const auto& t : pfs.RepTypes() )
		{
		ASSERT(types.HasKey(t));
		TypePtr tp{NewRef{}, (Type*)(t)};
		RegisterType(tp);
		}

	// The scaffolding is now in place to go ahead and generate
	// the functions & lambdas.  First declare them ...
	for ( const auto& func : funcs )
		if ( ! func.ShouldSkip() )
			DeclareFunc(func);

	// We track lambdas by their internal names, because two different
	// LambdaExpr's can wind up referring to the same underlying lambda
	// if the bodies happen to be identical.  In that case, we don't
	// want to generate the lambda twice.
	unordered_set<string> lambda_names;
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
		if ( ! func.ShouldSkip() )
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

	NL();
	Emit("std::vector<CPP_RegisterBody> CPP__bodies_to_register = {");

	for ( const auto& f : compiled_funcs )
		RegisterCompiledBody(f);

	Emit("};");

	GenEpilog();
	}

void CPPCompile::GenProlog()
	{
	if ( addl_tag <= 1 )
		// This is either a compilation via gen-C++, or
		// one using add-C++ and an empty CPP-gen.cc file.
		Emit("#include \"zeek/script_opt/CPP/Runtime.h\"\n");

	Emit("namespace zeek::detail { //\n");
	Emit("namespace CPP_%s { // %s\n", Fmt(addl_tag), working_dir);

	// The following might-or-might-not wind up being populated/used.
	Emit("std::vector<int> field_mapping;");
	Emit("std::vector<int> enum_mapping;");
	NL();

	const_info[TYPE_BOOL] = CreateConstInitInfo("Bool", "ValPtr", "bool");
	const_info[TYPE_INT] = CreateConstInitInfo("Int", "ValPtr", "zeek_int_t");
	const_info[TYPE_COUNT] = CreateConstInitInfo("Count", "ValPtr", "zeek_uint_t");
	const_info[TYPE_DOUBLE] = CreateConstInitInfo("Double", "ValPtr", "double");
	const_info[TYPE_TIME] = CreateConstInitInfo("Time", "ValPtr", "double");
	const_info[TYPE_INTERVAL] = CreateConstInitInfo("Interval", "ValPtr", "double");
	const_info[TYPE_ADDR] = CreateConstInitInfo("Addr", "ValPtr", "");
	const_info[TYPE_SUBNET] = CreateConstInitInfo("SubNet", "ValPtr", "");
	const_info[TYPE_PORT] = CreateConstInitInfo("Port", "ValPtr", "uint32_t");

	const_info[TYPE_ENUM] = CreateCompoundInitInfo("Enum", "ValPtr");
	const_info[TYPE_STRING] = CreateCompoundInitInfo("String", "ValPtr");
	const_info[TYPE_LIST] = CreateCompoundInitInfo("List", "ValPtr");
	const_info[TYPE_PATTERN] = CreateCompoundInitInfo("Pattern", "ValPtr");
	const_info[TYPE_VECTOR] = CreateCompoundInitInfo("Vector", "ValPtr");
	const_info[TYPE_RECORD] = CreateCompoundInitInfo("Record", "ValPtr");
	const_info[TYPE_TABLE] = CreateCompoundInitInfo("Table", "ValPtr");
	const_info[TYPE_FUNC] = CreateCompoundInitInfo("Func", "ValPtr");
	const_info[TYPE_FILE] = CreateCompoundInitInfo("File", "ValPtr");

	type_info = CreateCompoundInitInfo("Type", "Ptr");
	attr_info = CreateCompoundInitInfo("Attr", "Ptr");
	attrs_info = CreateCompoundInitInfo("Attributes", "Ptr");

	call_exprs_info = CreateCustomInitInfo("CallExpr", "Ptr");
	lambda_reg_info = CreateCustomInitInfo("LambdaRegistration", "");
	global_id_info = CreateCustomInitInfo("GlobalID", "");

	NL();
	DeclareDynCPPStmt();
	NL();
	}

shared_ptr<CPP_InitsInfo> CPPCompile::CreateConstInitInfo(const char* tag, const char* type,
                                                          const char* c_type)
	{
	auto gi = make_shared<CPP_BasicConstInitsInfo>(tag, type, c_type);
	return RegisterInitInfo(tag, type, gi);
	}

shared_ptr<CPP_InitsInfo> CPPCompile::CreateCompoundInitInfo(const char* tag, const char* type)
	{
	auto gi = make_shared<CPP_CompoundInitsInfo>(tag, type);
	return RegisterInitInfo(tag, type, gi);
	}

shared_ptr<CPP_InitsInfo> CPPCompile::CreateCustomInitInfo(const char* tag, const char* type)
	{
	auto gi = make_shared<CPP_CustomInitsInfo>(tag, type);
	if ( type[0] == '\0' )
		gi->SetCPPType("void*");

	return RegisterInitInfo(tag, type, gi);
	}

shared_ptr<CPP_InitsInfo> CPPCompile::RegisterInitInfo(const char* tag, const char* type,
                                                       shared_ptr<CPP_InitsInfo> gi)
	{
	string v_type = type[0] ? (string(tag) + type) : "void*";
	Emit("std::vector<%s> CPP__%s__;", v_type, string(tag));
	all_global_info.insert(gi);
	return gi;
	}

void CPPCompile::RegisterCompiledBody(const string& f)
	{
	auto h = body_hashes[f];
	auto p = body_priorities[f];

	// Build up an initializer of the events relevant to the function.
	string events;
	auto be = body_events.find(f);
	if ( be != body_events.end() )
		for ( const auto& e : be->second )
			{
			if ( events.size() > 0 )
				events += ", ";
			events = events + "\"" + e + "\"";
			}

	events = string("{") + events + "}";

	auto fi = func_index.find(f);
	ASSERT(fi != func_index.end());
	auto type_signature = casting_index[fi->second];
	Emit("\tCPP_RegisterBody(\"%s\", (void*) %s, %s, %s, %s, std::vector<std::string>(%s)),", f, f,
	     Fmt(type_signature), Fmt(p), Fmt(h), events);
	}

void CPPCompile::GenEpilog()
	{
	NL();
	for ( const auto& ii : init_infos )
		GenInitExpr(ii.second);

	NL();
	GenCPPDynStmt();

	NL();
	for ( auto gi : all_global_info )
		gi->GenerateInitializers(this);

	NL();
	InitializeEnumMappings();

	NL();
	InitializeFieldMappings();

	NL();
	InitializeBiFs();

	NL();
	indices_mgr.Generate(this);

	NL();
	InitializeStrings();

	NL();
	InitializeHashes();

	NL();
	InitializeConsts();

	NL();
	GenLoadBiFs();

	NL();
	GenFinishInit();

	NL();
	GenRegisterBodies();

	NL();
	Emit("void init__CPP()");
	StartBlock();
	Emit("register_bodies__CPP();");
	EndBlock();

	if ( standalone )
		GenStandaloneActivation();

	GenInitHook();

	Emit("} // %s\n\n", scope_prefix(addl_tag));
	Emit("} // zeek::detail");
	}

void CPPCompile::GenCPPDynStmt()
	{
	Emit("ValPtr CPPDynStmt::Exec(Frame* f, StmtFlowType& flow)");

	StartBlock();

	Emit("flow = FLOW_RETURN;");

	Emit("switch ( type_signature )");
	StartBlock();
	for ( auto i = 0U; i < func_casting_glue.size(); ++i )
		{
		Emit("case %s:", to_string(i));
		StartBlock();
		auto& glue = func_casting_glue[i];

		auto invoke = string("(*(") + glue.cast + ")(func))(" + glue.args + ")";

		if ( glue.is_hook )
			{
			Emit("if ( ! %s )", invoke);
			StartBlock();
			Emit("flow = FLOW_BREAK;");
			EndBlock();
			Emit("return nullptr;");
			}

		else if ( IsNativeType(glue.yield) )
			GenInvokeBody(invoke, glue.yield);

		else
			Emit("return %s;", invoke);

		EndBlock();
		}

	Emit("default:");
	Emit("\treporter->InternalError(\"invalid type in CPPDynStmt::Exec\");");
	Emit("\treturn nullptr;");

	EndBlock();
	EndBlock();
	}

void CPPCompile::GenLoadBiFs()
	{
	Emit("void load_BiFs__CPP()");
	StartBlock();
	Emit("for ( auto& b : CPP__BiF_lookups__ )");
	Emit("\tb.ResolveBiF();");
	EndBlock();
	}

void CPPCompile::GenFinishInit()
	{
	Emit("void finish_init__CPP()");

	StartBlock();

	Emit("static bool did_init = false;");
	Emit("if ( did_init )");
	Emit("\treturn;");
	Emit("did_init = true;");

	NL();
	Emit("std::vector<std::vector<int>> InitIndices;");
	Emit("generate_indices_set(CPP__Indices__init, InitIndices);");

	Emit("std::map<TypeTag, std::shared_ptr<CPP_AbstractInitAccessor>> InitConsts;");

	NL();
	for ( const auto& ci : const_info )
		{
		auto& gi = ci.second;
		Emit("InitConsts.emplace(%s, std::make_shared<CPP_InitAccessor<%s>>(%s));",
		     TypeTagName(ci.first), gi->CPPType(), gi->InitsName());
		}

	Emit("InitsManager im(CPP__ConstVals, InitConsts, InitIndices, CPP__Strings, CPP__Hashes, "
	     "CPP__Type__, CPP__Attributes__, CPP__Attr__, CPP__CallExpr__);");

	NL();
	int max_cohort = 0;
	for ( auto gi : all_global_info )
		max_cohort = std::max(max_cohort, gi->MaxCohort());

	for ( auto c = 0; c <= max_cohort; ++c )
		for ( auto gi : all_global_info )
			if ( gi->CohortSize(c) > 0 )
				Emit("%s.InitializeCohort(&im, %s);", gi->InitializersName(), Fmt(c));

	// Populate mappings for dynamic offsets.
	NL();
	Emit("for ( auto& em : CPP__enum_mappings__ )");
	Emit("\tenum_mapping.push_back(em.ComputeOffset(&im));");
	NL();
	Emit("for ( auto& fm : CPP__field_mappings__ )");
	Emit("\tfield_mapping.push_back(fm.ComputeOffset(&im));");

	NL();
	Emit("load_BiFs__CPP();");

	EndBlock();
	}

void CPPCompile::GenRegisterBodies()
	{
	Emit("void register_bodies__CPP()");
	StartBlock();

	Emit("for ( auto& b : CPP__bodies_to_register )");
	StartBlock();
	Emit("auto f = make_intrusive<CPPDynStmt>(b.func_name.c_str(), b.func, b.type_signature);");
	Emit("register_body__CPP(f, b.priority, b.h, b.events, finish_init__CPP);");
	EndBlock();

	EndBlock();
	}

bool CPPCompile::IsCompilable(const FuncInfo& func, const char** reason)
	{
	if ( ! is_CPP_compilable(func.Profile(), reason) )
		return false;

	if ( reason )
		// Indicate that there's no fundamental reason it can't be
		// compiled.
		*reason = nullptr;

	if ( func.ShouldSkip() )
		return false;

	return true;
	}

	} // zeek::detail
