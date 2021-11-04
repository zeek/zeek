// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::DeclareFunc(const FuncInfo& func)
	{
	if ( ! IsCompilable(func) )
		return;

	auto fname = Canonicalize(BodyName(func).c_str()) + "_zf";
	auto pf = func.Profile();
	auto f = func.Func();
	const auto& body = func.Body();
	auto priority = func.Priority();

	DeclareSubclass(f->GetType(), pf, fname, body, priority, nullptr, f->Flavor());

	if ( f->GetBodies().size() == 1 )
		compiled_simple_funcs[f->Name()] = fname;
	}

void CPPCompile::DeclareLambda(const LambdaExpr* l, const ProfileFunc* pf)
	{
	ASSERT(is_CPP_compilable(pf));

	auto lname = Canonicalize(l->Name().c_str()) + "_lb";
	auto body = l->Ingredients().body;
	auto l_id = l->Ingredients().id;
	auto& ids = l->OuterIDs();

	for ( auto id : ids )
		lambda_names[id] = LocalName(id);

	DeclareSubclass(l_id->GetType<FuncType>(), pf, lname, body, 0, l, FUNC_FLAVOR_FUNCTION);
	}

void CPPCompile::DeclareSubclass(const FuncTypePtr& ft, const ProfileFunc* pf, const string& fname,
                                 const StmtPtr& body, int priority, const LambdaExpr* l,
                                 FunctionFlavor flavor)
	{
	const auto& yt = ft->Yield();
	in_hook = flavor == FUNC_FLAVOR_HOOK;
	const IDPList* lambda_ids = l ? &l->OuterIDs() : nullptr;

	auto yt_decl = in_hook ? "bool" : FullTypeName(yt);

	NL();
	Emit("static %s %s(%s);", yt_decl, fname, ParamDecl(ft, lambda_ids, pf));

	Emit("class %s_cl : public CPPStmt", fname);
	StartBlock();

	Emit("public:");

	string addl_args; // captures passed in on construction
	string inits; // initializers for corresponding member vars

	if ( lambda_ids )
		{
		for ( auto& id : *lambda_ids )
			{
			auto name = lambda_names[id];
			auto tn = FullTypeName(id->GetType());
			addl_args = addl_args + ", " + tn + " _" + name;

			inits = inits + ", " + name + "(_" + name + ")";
			}
		}

	Emit("%s_cl(const char* name%s) : CPPStmt(name)%s { }", fname, addl_args.c_str(),
	     inits.c_str());

	// An additional constructor just used to generate place-holder
	// instances, due to the mis-design that lambdas are identified
	// by their Func objects rather than their FuncVal objects.
	if ( lambda_ids && lambda_ids->length() > 0 )
		Emit("%s_cl(const char* name) : CPPStmt(name) { }", fname);

	Emit("ValPtr Exec(Frame* f, StmtFlowType& flow) override final");
	StartBlock();

	Emit("flow = FLOW_RETURN;");

	if ( in_hook )
		{
		Emit("if ( ! %s(%s) )", fname, BindArgs(ft, lambda_ids));
		StartBlock();
		Emit("flow = FLOW_BREAK;");
		EndBlock();
		Emit("return nullptr;");
		}

	else if ( IsNativeType(yt) )
		GenInvokeBody(fname, yt, BindArgs(ft, lambda_ids));

	else
		Emit("return %s(%s);", fname, BindArgs(ft, lambda_ids));

	EndBlock();

	if ( lambda_ids )
		BuildLambda(ft, pf, fname, body, l, lambda_ids);
	else
		{
		// Track this function as known to have been compiled.
		// We don't track lambda bodies as compiled because they
		// can't be instantiated directly without also supplying
		// the captures.  In principle we could make an exception
		// for lambdas that don't take any arguments, but that
		// seems potentially more confusing than beneficial.
		compiled_funcs.emplace(fname);

		auto loc_f = script_specific_filename(body);
		cf_locs[fname] = loc_f;

		// Some guidance for those looking through the generated code.
		Emit("// compiled body for: %s", loc_f);
		}

	EndBlock(true);

	auto h = pf->HashVal();

	body_hashes[fname] = h;
	body_priorities[fname] = priority;
	body_names.emplace(body.get(), fname);
	names_to_bodies.emplace(fname, body.get());

	total_hash = merge_p_hashes(total_hash, h);
	}

void CPPCompile::BuildLambda(const FuncTypePtr& ft, const ProfileFunc* pf, const string& fname,
                             const StmtPtr& body, const LambdaExpr* l, const IDPList* lambda_ids)
	{
	// Declare the member variables for holding the captures.
	for ( auto& id : *lambda_ids )
		{
		auto name = lambda_names[id];
		auto tn = FullTypeName(id->GetType());
		Emit("%s %s;", tn, name.c_str());
		}

	// Generate initialization to create and register the lambda.
	auto literal_name = string("\"") + l->Name() + "\"";
	auto instantiate = string("make_intrusive<") + fname + "_cl>(" + literal_name + ")";

	int nl = lambda_ids->length();
	auto h = Fmt(pf->HashVal());
	auto has_captures = nl > 0 ? "true" : "false";
	auto l_init = string("register_lambda__CPP(") + instantiate + ", " + h + ", \"" + l->Name() +
	              "\", " + GenTypeName(ft) + ", " + has_captures + ");";

	AddInit(l, l_init);
	NoteInitDependency(l, TypeRep(ft));

	// Make the lambda's body's initialization depend on the lambda's
	// initialization.  That way GenFuncVarInits() can generate
	// initializations with the assurance that the associated body
	// hashes will have been registered.
	AddInit(body.get());
	NoteInitDependency(body.get(), l);

	// Generate method to extract the lambda captures from a deserialized
	// Frame object.
	Emit("void SetLambdaCaptures(Frame* f) override");
	StartBlock();
	for ( int i = 0; i < nl; ++i )
		{
		auto l_i = (*lambda_ids)[i];
		const auto& t_i = l_i->GetType();
		auto cap_i = string("f->GetElement(") + Fmt(i) + ")";
		Emit("%s = %s;", lambda_names[l_i], GenericValPtrToGT(cap_i, t_i, GEN_NATIVE));
		}
	EndBlock();

	// Generate the method for serializing the captures.
	Emit("std::vector<ValPtr> SerializeLambdaCaptures() const override");
	StartBlock();
	Emit("std::vector<ValPtr> vals;");
	for ( int i = 0; i < nl; ++i )
		{
		auto l_i = (*lambda_ids)[i];
		const auto& t_i = l_i->GetType();
		Emit("vals.emplace_back(%s);", NativeToGT(lambda_names[l_i], t_i, GEN_VAL_PTR));
		}
	Emit("return vals;");
	EndBlock();

	// Generate the Clone() method.
	Emit("CPPStmtPtr Clone() override");
	StartBlock();
	auto arg_clones = GenLambdaClone(l, true);
	Emit("return make_intrusive<%s_cl>(name.c_str()%s);", fname, arg_clones);
	EndBlock();
	}

string CPPCompile::BindArgs(const FuncTypePtr& ft, const IDPList* lambda_ids)
	{
	const auto& params = ft->Params();
	auto t = params->Types();

	string res;

	int n = t ? t->size() : 0;
	for ( auto i = 0; i < n; ++i )
		{
		auto arg_i = string("f->GetElement(") + Fmt(i) + ")";
		const auto& pt = params->GetFieldType(i);

		if ( IsNativeType(pt) )
			res += arg_i + NativeAccessor(pt);
		else
			res += GenericValPtrToGT(arg_i, pt, GEN_VAL_PTR);

		res += ", ";
		}

	if ( lambda_ids )
		{
		for ( auto& id : *lambda_ids )
			res += lambda_names[id] + ", ";
		}

	// Add the final frame argument.
	return res + "f";
	}

string CPPCompile::ParamDecl(const FuncTypePtr& ft, const IDPList* lambda_ids,
                             const ProfileFunc* pf)
	{
	const auto& params = ft->Params();
	int n = params->NumFields();

	string decl;

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = params->GetFieldType(i);
		auto tn = FullTypeName(t);
		auto param_id = FindParam(i, pf);
		string fn;

		if ( param_id )
			{
			if ( t->Tag() == TYPE_ANY && param_id->GetType()->Tag() != TYPE_ANY )
				// We'll need to translate the parameter
				// from its current representation to
				// type "any".
				fn = string("any_param__CPP_") + Fmt(i);
			else
				fn = LocalName(param_id);
			}
		else
			// Parameters that are unused don't wind up
			// in the ProfileFunc.  Rather than dig their
			// name out of the function's declaration, we
			// explicitly name them to reflect that they're
			// unused.
			fn = string("unused_param__CPP_") + Fmt(i);

		if ( IsNativeType(t) )
			// Native types are always pass-by-value.
			decl = decl + tn + " " + fn;
		else
			{
			if ( param_id && pf->Assignees().count(param_id) > 0 )
				// We modify the parameter.
				decl = decl + tn + " " + fn;
			else
				// Not modified, so pass by const reference.
				decl = decl + "const " + tn + "& " + fn;
			}

		decl += ", ";
		}

	if ( lambda_ids )
		{
		// Add the captures as additional parameters.
		for ( auto& id : *lambda_ids )
			{
			auto name = lambda_names[id];
			const auto& t = id->GetType();
			auto tn = FullTypeName(t);

			// Allow the captures to be modified.
			decl = decl + tn + "& " + name + ", ";
			}
		}

	// Add in the declaration of the frame.
	return decl + "Frame* f__CPP";
	}

const ID* CPPCompile::FindParam(int i, const ProfileFunc* pf)
	{
	const auto& params = pf->Params();

	for ( const auto& p : params )
		if ( p->Offset() == i )
			return p;

	return nullptr;
	}

	} // zeek::detail
