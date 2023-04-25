// See the file "COPYING" in the main distribution directory for copyright.

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

	CreateFunction(f->GetType(), pf, fname, body, priority, nullptr, f->Flavor());

	if ( f->GetBodies().size() == 1 )
		compiled_simple_funcs[f->Name()] = fname;
	}

void CPPCompile::DeclareLambda(const LambdaExpr* l, const ProfileFunc* pf)
	{
	ASSERT(is_CPP_compilable(pf));

	auto lname = Canonicalize(l->Name().c_str()) + "_lb";
	auto body = l->Ingredients().Body();
	auto l_id = l->Ingredients().GetID();
	auto& ids = l->OuterIDs();

	for ( auto id : ids )
		lambda_names[id] = LocalName(id);

	CreateFunction(l_id->GetType<FuncType>(), pf, lname, body, 0, l, FUNC_FLAVOR_FUNCTION);
	}

void CPPCompile::CreateFunction(const FuncTypePtr& ft, const ProfileFunc* pf, const string& fname,
                                const StmtPtr& body, int priority, const LambdaExpr* l,
                                FunctionFlavor flavor)
	{
	const auto& yt = ft->Yield();
	in_hook = flavor == FUNC_FLAVOR_HOOK;
	const IDPList* lambda_ids = l ? &l->OuterIDs() : nullptr;

	string args = BindArgs(ft, lambda_ids);

	auto yt_decl = in_hook ? "bool" : FullTypeName(yt);

	vector<string> p_types;
	GatherParamTypes(p_types, ft, lambda_ids, pf);

	string cast = string(yt_decl) + "(*)(";
	for ( auto& pt : p_types )
		cast += pt + ", ";
	cast += string("Frame*)");

	// We need to distinguish between hooks and non-hooks that happen
	// to have matching type signatures.  They'll be equivalent if they
	// have identical cast's.  To keep them separate, we cheat and
	// make hook casts different, string-wise, without altering their
	// semantics.
	if ( in_hook )
		cast += " ";

	func_index[fname] = cast;

	if ( ! l && casting_index.count(cast) == 0 )
		{
		casting_index[cast] = func_casting_glue.size();

		DispatchInfo di;
		di.cast = cast;
		di.args = args;
		di.is_hook = in_hook;
		di.yield = yt;

		func_casting_glue.emplace_back(di);
		}

	if ( lambda_ids )
		{
		DeclareSubclass(ft, pf, fname, args, lambda_ids);
		BuildLambda(ft, pf, fname, body, l, lambda_ids);
		EndBlock(true);
		}
	else
		{
		Emit("static %s %s(%s);", yt_decl, fname, ParamDecl(ft, lambda_ids, pf));

		// Track this function as known to have been compiled.
		// We don't track lambda bodies as compiled because they
		// can't be instantiated directly without also supplying
		// the captures.  In principle we could make an exception
		// for lambdas that don't take any arguments, but that
		// seems potentially more confusing than beneficial.
		compiled_funcs.emplace(fname);
		}

	body_hashes[fname] = pf->HashVal();
	body_priorities[fname] = priority;
	body_locs[fname] = body->GetLocationInfo();
	body_names.emplace(body.get(), fname);
	}

void CPPCompile::DeclareSubclass(const FuncTypePtr& ft, const ProfileFunc* pf, const string& fname,
                                 const string& args, const IDPList* lambda_ids)
	{
	const auto& yt = ft->Yield();

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

	const Obj* stmts = pf->ProfiledBody();
	if ( ! stmts )
		stmts = pf->ProfiledExpr();

	auto loc = stmts->GetLocationInfo();
	auto loc_info = string("\"") + loc->filename + "\", " + Fmt(loc->first_line);
	Emit("%s_cl(const char* name%s) : CPPStmt(name, %s)%s { }", fname, addl_args, loc_info, inits);

	// An additional constructor just used to generate place-holder
	// instances, due to the mis-design that lambdas are identified
	// by their Func objects rather than their FuncVal objects.
	if ( lambda_ids && lambda_ids->length() > 0 )
		Emit("%s_cl(const char* name) : CPPStmt(name, %s) { }", fname, loc_info);

	Emit("ValPtr Exec(Frame* f, StmtFlowType& flow) override final");
	StartBlock();

	Emit("flow = FLOW_RETURN;");

	if ( in_hook )
		{
		Emit("if ( ! %s(%s) )", fname, args);
		StartBlock();
		Emit("flow = FLOW_BREAK;");
		EndBlock();
		Emit("return nullptr;");
		}

	else if ( IsNativeType(yt) )
		GenInvokeBody(fname, yt, args);

	else
		Emit("return %s(%s);", fname, args);

	EndBlock();
	}

void CPPCompile::DeclareDynCPPStmt()
	{
	Emit("// A version of CPPStmt that manages a function pointer and");
	Emit("// dynamically casts it to a given type to call it via Exec().");
	Emit("// We will later generate a custom Exec method to support this");
	Emit("// dispatch.  All of this is ugly, and only needed because clang");
	Emit("// goes nuts (super slow) in the face of thousands of templates");
	Emit("// in a given context (initializers, or a function body).");
	Emit("class CPPDynStmt : public CPPStmt");
	Emit("\t{");
	Emit("public:");
	Emit("\tCPPDynStmt(const char* _name, void* _func, int _type_signature, const char* filename, "
	     "int line_num) : CPPStmt(_name, filename, line_num), "
	     "func(_func), type_signature(_type_signature) { }");
	Emit("\tValPtr Exec(Frame* f, StmtFlowType& flow) override final;");
	Emit("private:");
	Emit("\t// The function to call in Exec().");
	Emit("\tvoid* func;");
	Emit("\t// Used via a switch in the dynamically-generated Exec() method");
	Emit("\t// to cast func to the write type, and to call it with the");
	Emit("\t// right arguments pulled out of the frame.");
	Emit("\tint type_signature;");
	Emit("\t};");
	}

void CPPCompile::BuildLambda(const FuncTypePtr& ft, const ProfileFunc* pf, const string& fname,
                             const StmtPtr& body, const LambdaExpr* l, const IDPList* lambda_ids)
	{
	// Declare the member variables for holding the captures.
	for ( auto& id : *lambda_ids )
		{
		auto name = lambda_names[id];
		auto tn = FullTypeName(id->GetType());
		Emit("%s %s;", tn, name);
		}

	// Generate initialization to create and register the lambda.
	auto h = pf->HashVal();
	auto nl = lambda_ids->length();
	bool has_captures = nl > 0;

	auto gi = make_shared<LambdaRegistrationInfo>(this, l->Name(), ft, fname + "_cl", h,
	                                              has_captures);
	lambda_reg_info->AddInstance(gi);

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
	vector<string> p_types;
	vector<string> p_names;

	GatherParamTypes(p_types, ft, lambda_ids, pf);
	GatherParamNames(p_names, ft, lambda_ids, pf);

	ASSERT(p_types.size() == p_names.size());

	string decl;

	for ( auto i = 0U; i < p_types.size(); ++i )
		decl += p_types[i] + " " + p_names[i] + ", ";

	// Add in the declaration of the frame.
	return decl + "Frame* f__CPP";
	}

void CPPCompile::GatherParamTypes(vector<string>& p_types, const FuncTypePtr& ft,
                                  const IDPList* lambda_ids, const ProfileFunc* pf)
	{
	const auto& params = ft->Params();
	int n = params->NumFields();

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = params->GetFieldType(i);
		auto tn = FullTypeName(t);
		auto param_id = FindParam(i, pf);

		if ( IsNativeType(t) )
			// Native types are always pass-by-value.
			p_types.emplace_back(tn);
		else
			{
			if ( param_id && pf->Assignees().count(param_id) > 0 )
				// We modify the parameter.
				p_types.emplace_back(tn);
			else
				// Not modified, so pass by const reference.
				p_types.emplace_back(string("const ") + tn + "&");
			}
		}

	if ( lambda_ids )
		// Add the captures as additional parameters.
		for ( auto& id : *lambda_ids )
			{
			const auto& t = id->GetType();
			auto tn = FullTypeName(t);

			// Allow the captures to be modified.
			p_types.emplace_back(string(tn) + "& ");
			}
	}

void CPPCompile::GatherParamNames(vector<string>& p_names, const FuncTypePtr& ft,
                                  const IDPList* lambda_ids, const ProfileFunc* pf)
	{
	const auto& params = ft->Params();
	int n = params->NumFields();

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = params->GetFieldType(i);
		auto param_id = FindParam(i, pf);

		if ( param_id )
			{
			if ( t->Tag() == TYPE_ANY && param_id->GetType()->Tag() != TYPE_ANY )
				// We'll need to translate the parameter
				// from its current representation to
				// type "any".
				p_names.emplace_back(string("any_param__CPP_") + Fmt(i));
			else
				p_names.emplace_back(LocalName(param_id));
			}
		else
			// Parameters that are unused don't wind up in the
			//  ProfileFunc.  Rather than dig their name out of
			// the function's declaration, we explicitly name
			// them to reflect that they're unused.
			p_names.emplace_back(string("unused_param__CPP_") + Fmt(i));
		}

	if ( lambda_ids )
		// Add the captures as additional parameters.
		for ( auto& id : *lambda_ids )
			p_names.emplace_back(lambda_names[id]);
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
