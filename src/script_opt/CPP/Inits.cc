// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/module_util.h"
#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail
	{

using namespace std;

std::shared_ptr<CPP_InitInfo> CPPCompile::RegisterInitExpr(const ExprPtr& ep)
	{
	auto ename = InitExprName(ep);

	auto ii = init_infos.find(ename);
	if ( ii != init_infos.end() )
		return ii->second;

	auto wrapper_cl = string("wrapper_") + ename + "_cl";

	auto gi = make_shared<CallExprInitInfo>(this, ep, ename, wrapper_cl);
	call_exprs_info->AddInstance(gi);
	init_infos[ename] = gi;

	return gi;
	}

void CPPCompile::GenInitExpr(std::shared_ptr<CallExprInitInfo> ce_init)
	{
	NL();

	const auto& e = ce_init->GetExpr();
	const auto& t = e->GetType();
	const auto& ename = ce_init->Name();
	const auto& wc = ce_init->WrapperClass();

	// First, create a CPPFunc that we can compile to compute 'e'.
	auto name = string("wrapper_") + ename;

	// Forward declaration of the function that computes 'e'.
	Emit("static %s %s(Frame* f__CPP);", FullTypeName(t), name);

	// Create the Func subclass that can be used in a CallExpr to
	// evaluate 'e'.
	Emit("class %s : public CPPFunc", wc);
	StartBlock();

	Emit("public:");
	Emit("%s() : CPPFunc(\"%s\", %s)", wc, name, e->IsPure() ? "true" : "false");

	StartBlock();
	Emit("type = make_intrusive<FuncType>(make_intrusive<RecordType>(new type_decl_list()), %s, "
	     "FUNC_FLAVOR_FUNCTION);",
	     GenTypeName(t));

	EndBlock();

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override final");
	StartBlock();

	if ( IsNativeType(t) )
		GenInvokeBody(name, t, "parent");
	else
		Emit("return %s(parent);", name);

	EndBlock();
	EndBlock(true);

	// Now the implementation of computing 'e'.
	Emit("static %s %s(Frame* f__CPP)", FullTypeName(t), name);
	StartBlock();

	Emit("return %s;", GenExpr(e, GEN_NATIVE));
	EndBlock();

	Emit("CallExprPtr %s;", ename);
	}

bool CPPCompile::IsSimpleInitExpr(const ExprPtr& e)
	{
	switch ( e->Tag() )
		{
		case EXPR_CONST:
		case EXPR_NAME:
			return true;

		case EXPR_RECORD_COERCE:
			{ // look for coercion of empty record
			auto op = e->GetOp1();

			if ( op->Tag() != EXPR_RECORD_CONSTRUCTOR )
				return false;

			auto rc = static_cast<const RecordConstructorExpr*>(op.get());
			const auto& exprs = rc->Op()->AsListExpr()->Exprs();

			return exprs.length() == 0;
			}

		default:
			return false;
		}
	}

string CPPCompile::InitExprName(const ExprPtr& e)
	{
	return init_exprs.KeyName(e);
	}

void CPPCompile::InitializeFieldMappings()
	{
	Emit("std::vector<CPP_FieldMapping> CPP__field_mappings__ = ");

	StartBlock();

	for ( const auto& mapping : field_decls )
		{
		auto rt_arg = Fmt(mapping.first);
		auto td = mapping.second;
		auto type_arg = Fmt(TypeOffset(td->type));
		auto attrs_arg = Fmt(AttributesOffset(td->attrs));

		Emit("CPP_FieldMapping(%s, \"%s\", %s, %s),", rt_arg, td->id, type_arg, attrs_arg);
		}

	EndBlock(true);
	}

void CPPCompile::InitializeEnumMappings()
	{
	Emit("std::vector<CPP_EnumMapping> CPP__enum_mappings__ = ");

	StartBlock();

	for ( const auto& mapping : enum_names )
		Emit("CPP_EnumMapping(%s, \"%s\"),", Fmt(mapping.first), mapping.second);

	EndBlock(true);
	}

void CPPCompile::InitializeBiFs()
	{
	Emit("std::vector<CPP_LookupBiF> CPP__BiF_lookups__ = ");

	StartBlock();

	for ( const auto& b : BiFs )
		Emit("CPP_LookupBiF(%s, \"%s\"),", b.first, b.second);

	EndBlock(true);
	}

void CPPCompile::InitializeStrings()
	{
	Emit("std::vector<const char*> CPP__Strings =");

	StartBlock();

	for ( const auto& s : ordered_tracked_strings )
		Emit("\"%s\",", s);

	EndBlock(true);
	}

void CPPCompile::InitializeHashes()
	{
	Emit("std::vector<p_hash_type> CPP__Hashes =");

	StartBlock();

	for ( const auto& h : ordered_tracked_hashes )
		Emit(Fmt(h) + ",");

	EndBlock(true);
	}

void CPPCompile::InitializeConsts()
	{
	Emit("std::vector<CPP_ValElem> CPP__ConstVals =");

	StartBlock();

	for ( const auto& c : consts )
		Emit("CPP_ValElem(%s, %s),", TypeTagName(c.first), Fmt(c.second));

	EndBlock(true);
	}

void CPPCompile::InitializeGlobals()
	{
	Emit("static void init_globals__CPP()");
	StartBlock();

	Emit("Frame* f__CPP = nullptr;");
	NL();

	for ( const auto& ginit : IDOptInfo::GetGlobalInitExprs() )
		{
		auto g = ginit.Id();
		if ( pfs.Globals().count(g) == 0 )
			continue;

		auto ic = ginit.IC();
		auto& init = ginit.Init();

		if ( ic == INIT_NONE )
			Emit(GenExpr(init, GEN_NATIVE, true) + ";");

		else
			{
			// This branch occurs for += or -= initializations that
			// use associated functions.
			string ics;
			if ( ic == INIT_EXTRA )
				ics = "INIT_EXTRA";
			else if ( ic == INIT_REMOVE )
				ics = "INIT_REMOVE";
			else
				reporter->FatalError("bad initialization class in CPPCompile::InitializeGlobals()");

			Emit("%s->SetValue(%s, %s);", globals[g->Name()], GenExpr(init, GEN_NATIVE, true), ics);
			}

		const auto& attrs = g->GetAttrs();
		if ( attrs )
			{
			string attr_tags;
			string attr_vals;
			BuildAttrs(attrs, attr_tags, attr_vals);
			Emit("assign_attrs__CPP(%s, %s, %s);", globals[g->Name()], attr_tags, attr_vals);
			}
		}

	EndBlock();
	}

void CPPCompile::GenInitHook()
	{
	NL();

	Emit("int hook_in_init()");

	StartBlock();

	Emit("CPP_init_funcs.push_back(init__CPP);");

	if ( standalone )
		GenLoad();

	Emit("return 0;");
	EndBlock();

	// Trigger the activation of the hook at run-time.
	NL();
	Emit("static int dummy = hook_in_init();\n");
	}

void CPPCompile::GenStandaloneActivation()
	{
	NL();

	Emit("void standalone_activation__CPP()");
	StartBlock();

	Emit("finish_init__CPP();");
	NL();

	// For events and hooks, we need to add each compiled body *unless*
	// it's already there (which could be the case if the standalone
	// code wasn't run standalone but instead with the original scripts).
	// For events, we also register them in order to activate the
	// associated scripts.

	// First, build up a list of per-hook/event handler bodies.
	unordered_map<const Func*, vector<p_hash_type>> func_bodies;

	for ( const auto& func : funcs )
		{
		if ( func.ShouldSkip() )
			continue;

		auto f = func.Func();
		auto fname = BodyName(func);
		auto bname = Canonicalize(fname.c_str()) + "_zf";

		if ( compiled_funcs.count(bname) == 0 )
			// We didn't wind up compiling it.
			continue;

		auto bh = body_hashes.find(bname);
		ASSERT(bh != body_hashes.end());
		func_bodies[f].push_back(bh->second);
		}

	for ( auto& fb : func_bodies )
		{
		string hashes;
		for ( auto h : fb.second )
			{
			if ( hashes.size() > 0 )
				hashes += ", ";

			hashes += Fmt(h);
			}

		hashes = "{" + hashes + "}";

		auto f = fb.first;
		auto fn = f->Name();
		const auto& ft = f->GetType();

		auto var = extract_var_name(fn);
		auto mod = extract_module_name(fn);

		auto fid = lookup_ID(var.c_str(), mod.c_str(), false, true, false);
		if ( ! fid )
			reporter->InternalError("can't find identifier %s", fn);

		auto exported = fid->IsExport() ? "true" : "false";

		Emit("activate_bodies__CPP(\"%s\", \"%s\", %s, %s, %s);", var, mod, exported,
		     GenTypeName(ft), hashes);
		}

	EndBlock();

	NL();
	Emit("void standalone_init__CPP()");
	StartBlock();
	Emit("init__CPP();");
	Emit("standalone_activation__CPP();");
	Emit("standalone_finalizations.push_back(load_BiFs__CPP);");
	EndBlock();
	}

void CPPCompile::GenLoad()
	{
	Emit("register_scripts__CPP(%s, standalone_init__CPP);", Fmt(total_hash));
	printf("global init_CPP_%llu = load_CPP(%llu);\n", total_hash, total_hash);
	}

	} // zeek::detail
