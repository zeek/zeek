// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zeek/module_util.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/CPP/Compile.h"


namespace zeek::detail {

using namespace std;

void CPPCompile::GenInitExpr(const ExprPtr& e)
	{
	NL();

	const auto& t = e->GetType();
	auto ename = InitExprName(e);

	// First, create a CPPFunc that we can compile to compute 'e'.
	auto name = string("wrapper_") + ename;

	// Forward declaration of the function that computes 'e'.
	Emit("static %s %s(Frame* f__CPP);", FullTypeName(t), name);

	// Create the Func subclass that can be used in a CallExpr to
	// evaluate 'e'.
	Emit("class %s_cl : public CPPFunc", name);
	StartBlock();

	Emit("public:");
	Emit("%s_cl() : CPPFunc(\"%s\", %s)", name, name, e->IsPure() ? "true" : "false");

	StartBlock();
	Emit("type = make_intrusive<FuncType>(make_intrusive<RecordType>(new type_decl_list()), %s, FUNC_FLAVOR_FUNCTION);", GenTypeName(t));

	NoteInitDependency(e, TypeRep(t));
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

	NoteInitDependency(e, TypeRep(t));
	AddInit(e, ename, string("make_intrusive<CallExpr>(make_intrusive<ConstExpr>(make_intrusive<FuncVal>(make_intrusive<") +
		name + "_cl>())), make_intrusive<ListExpr>(), false)");
	}

bool CPPCompile::IsSimpleInitExpr(const ExprPtr& e) const
	{
	switch ( e->Tag() ) {
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

void CPPCompile::GenGlobalInit(const ID* g, string& gl, const ValPtr& v)
	{
	const auto& t = v->GetType();
	auto tag = t->Tag();

	if ( tag == TYPE_FUNC )
		// This should get initialized by recognizing hash of
		// the function's body.
		return;

	string init_val;
	if ( tag == TYPE_OPAQUE )
		{
		// We can only generate these by reproducing the expression
		// (presumably a function call) used to create the value.
		// That isn't fully sound, since if the global's value
		// was redef'd in terms of its original value (e.g.,
		// "redef x = f(x)"), then we'll wind up with a broken
		// expression.  It's difficult to detect that in full
		// generality, so um Don't Do That.  (Note that this
		// only affects execution of standalone compiled code,
		// where the original scripts are replaced by load-stubs.
		// If the scripts are available, then the HasVal() test
		// we generate will mean we don't wind up using this
		// expression anyway.)

		// Use the final initialization expression.
		auto& init_exprs = g->GetOptInfo()->GetInitExprs();
		init_val = GenExpr(init_exprs.back(), GEN_VAL_PTR, false);
		}
	else
		init_val = BuildConstant(g, v);

	auto& attrs = g->GetAttrs();

	AddInit(g, string("if ( ! ") + gl + "->HasVal() )");

	if ( attrs )
		{
		RegisterAttributes(attrs);

		AddInit(g, "\t{");
		AddInit(g, "\t" + gl + "->SetVal(" + init_val + ");");
		AddInit(g, "\t" + gl + "->SetAttrs(" + AttrsName(attrs) + ");");
		AddInit(g, "\t}");
		}
	else
		AddInit(g, "\t" + gl + "->SetVal(" + init_val + ");");
	}

void CPPCompile::GenFuncVarInits()
	{
	for ( const auto& fv_init : func_vars )
		{
		auto& fv = fv_init.first;
		auto& const_name = fv_init.second;

		auto f = fv->AsFunc();
		const auto& fn = f->Name();
		const auto& ft = f->GetType();

		NoteInitDependency(fv, TypeRep(ft));

		const auto& bodies = f->GetBodies();

		string hashes = "{";

		for ( const auto& b : bodies )
			{
			auto body = b.stmts.get();

			ASSERT(body_names.count(body) > 0);

			auto& body_name = body_names[body];
			ASSERT(body_hashes.count(body_name) > 0);

			NoteInitDependency(fv, body);

			if ( hashes.size() > 1 )
				hashes += ", ";

			hashes += Fmt(body_hashes[body_name]);
			}

		hashes += "}";

		auto init = string("lookup_func__CPP(\"") + fn +
			    "\", " + hashes + ", " + GenTypeName(ft) + ")";

		AddInit(fv, const_name, init);
		}
	}

void CPPCompile::GenPreInit(const Type* t)
	{
	string pre_init;

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ERROR:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_VOID:
		pre_init = string("base_type(") + TypeTagName(t->Tag()) + ")";
		break;

	case TYPE_ENUM:
		pre_init = string("get_enum_type__CPP(\"") +
		           t->GetName() + "\")";
		break;

	case TYPE_SUBNET:
		pre_init = string("make_intrusive<SubNetType>()");
		break;

	case TYPE_FILE:
		pre_init = string("make_intrusive<FileType>(") +
		           GenTypeName(t->AsFileType()->Yield()) + ")";
		break;

	case TYPE_OPAQUE:
		pre_init = string("make_intrusive<OpaqueType>(\"") +
		           t->AsOpaqueType()->Name() + "\")";
		break;

	case TYPE_RECORD:
		{
		string name;

		if ( t->GetName() != "" )
			name = string("\"") + t->GetName() + string("\"");
		else
			name = "nullptr";

		pre_init = string("get_record_type__CPP(") + name + ")";
		}
		break;

	case TYPE_LIST:
		pre_init = string("make_intrusive<TypeList>()");
		break;

	case TYPE_TYPE:
	case TYPE_VECTOR:
	case TYPE_TABLE:
	case TYPE_FUNC:
		// Nothing to do for these, pre-initialization-wise.
		return;

	default:
		reporter->InternalError("bad type in CPPCompile::GenType");
	}

	pre_inits.emplace_back(GenTypeName(t) + " = " + pre_init + ";");
	}

void CPPCompile::GenPreInits()
	{
	NL();
	Emit("void pre_init__CPP()");

	StartBlock();
	for ( const auto& i : pre_inits )
		Emit(i);
	EndBlock();
	}

void CPPCompile::AddInit(const Obj* o, const string& init)
	{
	obj_inits[o].emplace_back(init);
	}

void CPPCompile::AddInit(const Obj* o)
	{
	if ( obj_inits.count(o) == 0 )
		obj_inits[o] = {};
	}

void CPPCompile::NoteInitDependency(const Obj* o1, const Obj* o2)
	{
	obj_deps[o1].emplace(o2);
	}

void CPPCompile::CheckInitConsistency(unordered_set<const Obj*>& to_do)
	{
	for ( const auto& od : obj_deps )
		{
		const auto& o = od.first;

		if ( to_do.count(o) == 0 )
			{
			fprintf(stderr, "object not in to_do: %s\n",
				obj_desc(o).c_str());
			exit(1);
			}

		for ( const auto& d : od.second )
			{
			if ( to_do.count(d) == 0 )
				{
				fprintf(stderr, "dep object for %s not in to_do: %s\n",
					obj_desc(o).c_str(), obj_desc(d).c_str());
				exit(1);
				}
			}
		}
	}

int CPPCompile::GenDependentInits(unordered_set<const Obj*>& to_do)
	{
	int n = 0;

	// The basic approach is fairly brute force: find elements of
	// to_do that don't have any pending dependencies; generate those;
	// and remove them from the to_do list, freeing up other to_do entries
	// to now not having any pending dependencies.  Iterate until there
	// are no more to-do items.
	while ( to_do.size() > 0 )
		{
		unordered_set<const Obj*> cohort;

		for ( const auto& o : to_do )
			{
			const auto& od = obj_deps.find(o);

			bool has_pending_dep = false;

			if ( od != obj_deps.end() )
				{
				for ( const auto& d : od->second )
					if ( to_do.count(d) > 0 )
						{
						has_pending_dep = true;
						break;
						}
				}

			if ( has_pending_dep )
				continue;

			cohort.insert(o);
			}

		ASSERT(cohort.size() > 0);

		GenInitCohort(++n, cohort);

		for ( const auto& o : cohort )
			{
			ASSERT(to_do.count(o) > 0);
			to_do.erase(o);
			}
		}

	return n;
	}

void CPPCompile::GenInitCohort(int nc, unordered_set<const Obj*>& cohort)
	{
	NL();
	Emit("void init_%s__CPP()", Fmt(nc));
	StartBlock();

	// If any script/BiF functions are used for initializing globals,
	// the code generated from that will expect the presence of a
	// frame pointer, even if nil.
	Emit("Frame* f__CPP = nullptr;");

	// The following is just for making the output readable/pretty:
	// add space between initializations for distinct objects, taking
	// into account that some objects have empty initializations.
	bool did_an_init = false;

	for ( auto o : cohort )
		{
		if ( did_an_init )
			{
			NL();
			did_an_init = false;
			}

		for ( const auto& i : obj_inits.find(o)->second )
			{
			Emit("%s", i);
			did_an_init = true;
			}
		}

	EndBlock();
	}

void CPPCompile::InitializeFieldMappings()
	{
	Emit("int fm_offset;");

	for ( const auto& mapping : field_decls )
		{
		auto rt = mapping.first;
		auto td = mapping.second;
		auto fn = td->id;
		auto rt_name = GenTypeName(rt) + "->AsRecordType()";

		Emit("fm_offset = %s->FieldOffset(\"%s\");", rt_name, fn);
		Emit("if ( fm_offset < 0 )");

		StartBlock();
		Emit("// field does not exist, create it");
		Emit("fm_offset = %s->NumFields();", rt_name);
		Emit("type_decl_list tl;");
		Emit(GenTypeDecl(td));
		Emit("%s->AddFieldsDirectly(tl);", rt_name);
		EndBlock();

		Emit("field_mapping.push_back(fm_offset);");
		}
	}

void CPPCompile::InitializeEnumMappings()
	{
	int n = 0;

	for ( const auto& mapping : enum_names )
		InitializeEnumMappings(mapping.first, mapping.second, n++);
	}

void CPPCompile::InitializeEnumMappings(const EnumType* et,
                                        const string& e_name, int index)
	{
	AddInit(et, "{");

	auto et_name = GenTypeName(et) + "->AsEnumType()";
	AddInit(et, "int em_offset = " + et_name +
	            "->Lookup(\"" + e_name + "\");");
	AddInit(et, "if ( em_offset < 0 )");

	AddInit(et, "\t{");
	AddInit(et, "\tem_offset = " + et_name + "->Names().size();");
	// The following is to catch the case where the offset is already
	// in use due to it being specified explicitly for an existing enum.
	AddInit(et, "\tif ( " + et_name + "->Lookup(em_offset) )");
	AddInit(et, "\t\treporter->InternalError(\"enum inconsistency while initializing compiled scripts\");");
	AddInit(et, "\t" + et_name +
	            "->AddNameInternal(\"" + e_name + "\", em_offset);");
	AddInit(et, "\t}");

	AddInit(et, "enum_mapping[" + Fmt(index) + "] = em_offset;");

	AddInit(et, "}");
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
	for ( auto& a : activations )
		Emit(a);
	EndBlock();

	NL();
	Emit("void standalone_init__CPP()");
	StartBlock();

	// For events and hooks, we need to add each compiled body *unless*
	// it's already there (which could be the case if the standalone
	// code wasn't run standalone but instead with the original scripts).
	// For events, we also register them in order to activate the
	// associated scripts.

	// First, build up a list of per-hook/event handler bodies.
	unordered_map<const Func*, vector<p_hash_type>> func_bodies;

	for ( const auto& func : funcs )
		{
		auto f = func.Func();
		auto fname = BodyName(func);
		auto bname = Canonicalize(fname.c_str()) + "_zf";

		if ( compiled_funcs.count(bname) == 0 )
			// We didn't wind up compiling it.
			continue;

		ASSERT(body_hashes.count(bname) > 0);
		func_bodies[f].push_back(body_hashes[bname]);
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
		module_names.insert(mod);

		auto fid = lookup_ID(var.c_str(), mod.c_str(),
		                     false, true, false);
		if ( ! fid )
			reporter->InternalError("can't find identifier %s", fn);

		auto exported = fid->IsExport() ? "true" : "false";

		Emit("activate_bodies__CPP(\"%s\", \"%s\", %s, %s, %s);",
		     var, mod, exported, GenTypeName(ft), hashes);
		}

	NL();
	Emit("CPP_activation_funcs.push_back(standalone_activation__CPP);");
	Emit("CPP_activation_hook = activate__CPPs;");

	EndBlock();
	}

void CPPCompile::GenLoad()
	{
	// First, generate a hash unique to this compilation.
	auto t = util::current_time();
	auto th = hash<double>{}(t);

	total_hash = merge_p_hashes(total_hash, th);

	Emit("register_scripts__CPP(%s, standalone_init__CPP);", Fmt(total_hash));

	// Spit out the placeholder script, and any associated module
	// definitions.
	for ( const auto& m : module_names )
		if ( m != "GLOBAL" )
			printf("module %s;\n", m.c_str());

	if ( module_names.size() > 0 )
		printf("module GLOBAL;\n\n");

	printf("global init_CPP_%llu = load_CPP(%llu);\n",
	       total_hash, total_hash);
	}

} // zeek::detail
