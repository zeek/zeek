// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/RuntimeInitSupport.h"

#include "zeek/EventRegistry.h"
#include "zeek/module_util.h"

namespace zeek::detail
	{

using namespace std;

vector<CPP_init_func> CPP_init_funcs;

// Calls all of the initialization hooks, in the order they were added.
void init_CPPs()
	{
	static bool need_init = true;

	if ( need_init )
		for ( auto f : CPP_init_funcs )
			f();

	need_init = false;
	}

// This is a trick used to register the presence of compiled code.
// The initialization of the static variable will make CPP_init_hook
// non-null, which the main part of Zeek uses to tell that there's
// CPP code available.
static int flag_init_CPP()
	{
	CPP_init_hook = init_CPPs;
	return 0;
	}

static int dummy = flag_init_CPP();

void register_type__CPP(TypePtr t, const string& name)
	{
	if ( t->GetName().size() > 0 )
		// Already registered.
		return;

	t->SetName(name);

	auto id = install_ID(name.c_str(), GLOBAL_MODULE_NAME, true, false);
	id->SetType(t);
	id->MakeType();
	}

void register_body__CPP(CPPStmtPtr body, int priority, p_hash_type hash, vector<string> events,
                        void (*finish_init)())
	{
	compiled_scripts[hash] = {std::move(body), priority, std::move(events), finish_init};
	}

static unordered_map<p_hash_type, CompiledScript> compiled_standalone_scripts;

void register_standalone_body__CPP(CPPStmtPtr body, int priority, p_hash_type hash,
                                   vector<string> events, void (*finish_init)())
	{
	// For standalone scripts we don't actually need finish_init, but
	// we keep it for symmetry with compiled_scripts.
	compiled_standalone_scripts[hash] = {std::move(body), priority, std::move(events), finish_init};
	}

void register_lambda__CPP(CPPStmtPtr body, p_hash_type hash, const char* name, TypePtr t,
                          bool has_captures)
	{
	auto ft = cast_intrusive<FuncType>(t);

	// Create the quasi-global.
	auto id = install_ID(name, GLOBAL_MODULE_NAME, true, false);
	auto func = make_intrusive<CPPLambdaFunc>(name, ft, body);
	func->SetName(name);

	auto v = make_intrusive<FuncVal>(std::move(func));
	id->SetVal(std::move(v));
	id->SetType(ft);

	// Lambdas used in initializing global functions need to
	// be registered, so that the initialization can find them.
	// We do not, however, want to register *all* lambdas, because
	// the ones that use captures cannot be used as regular
	// function bodies.
	if ( ! has_captures )
		// Note, no support for lambdas that themselves refer
		// to events.
		register_body__CPP(body, 0, hash, {}, nullptr);
	}

void register_scripts__CPP(p_hash_type h, void (*callback)())
	{
	ASSERT(standalone_callbacks.count(h) == 0);
	standalone_callbacks[h] = callback;
	}

void activate_bodies__CPP(const char* fn, const char* module, bool exported, TypePtr t,
                          vector<p_hash_type> hashes)
	{
	auto ft = cast_intrusive<FuncType>(t);
	auto fg = lookup_ID(fn, module, false, false, false);

	if ( ! fg )
		{
		fg = install_ID(fn, module, true, exported);
		fg->SetType(ft);
		}

	if ( ! fg->GetAttr(ATTR_IS_USED) )
		fg->AddAttr(make_intrusive<Attr>(ATTR_IS_USED));

	auto v = fg->GetVal();
	if ( ! v )
		{ // Create it.
		vector<StmtPtr> no_bodies;
		vector<int> no_priorities;
		auto sf = make_intrusive<ScriptFunc>(fn, ft, no_bodies, no_priorities);

		v = make_intrusive<FuncVal>(std::move(sf));
		fg->SetVal(v);
		}

	auto f = v->AsFunc();

	// Events we need to register.
	unordered_set<string> events;

	if ( ft->Flavor() == FUNC_FLAVOR_EVENT )
		events.insert(fn);

	vector<detail::IDPtr> no_inits; // empty initialization vector
	int num_params = ft->Params()->NumFields();

	for ( auto h : hashes )
		{
		// Add in the new body.
		auto csi = compiled_standalone_scripts.find(h);
		ASSERT(csi != compiled_standalone_scripts.end());
		auto cs = csi->second;

		f->AddBody(cs.body, no_inits, num_params, cs.priority);
		added_bodies[fn].insert(h);

		events.insert(cs.events.begin(), cs.events.end());
		}

	for ( const auto& e : events )
		{
		auto eh = event_registry->Register(e);
		eh->SetUsed();
		}
	}

IDPtr lookup_global__CPP(const char* g, const TypePtr& t, bool exported)
	{
	auto gl = lookup_ID(g, GLOBAL_MODULE_NAME, false, false, false);

	if ( ! gl )
		{
		gl = install_ID(g, GLOBAL_MODULE_NAME, true, exported);
		gl->SetType(t);
		}

	return gl;
	}

Func* lookup_bif__CPP(const char* bif)
	{
	auto b = lookup_ID(bif, GLOBAL_MODULE_NAME, false, false, false);
	return (b && b->GetVal()) ? b->GetVal()->AsFunc() : nullptr;
	}

FuncValPtr lookup_func__CPP(string name, int num_bodies, vector<p_hash_type> hashes,
                            const TypePtr& t)
	{
	auto ft = cast_intrusive<FuncType>(t);

	if ( static_cast<int>(hashes.size()) < num_bodies )
		{
		// This happens for functions that have at least one
		// uncompilable body.
		auto gl = lookup_ID(name.c_str(), GLOBAL_MODULE_NAME, false, false, false);
		if ( ! gl )
			{
			reporter->CPPRuntimeError("non-compiled function %s missing", name.c_str());
			exit(1);
			}

		auto v = gl->GetVal();
		if ( ! v || v->GetType()->Tag() != TYPE_FUNC )
			{
			reporter->CPPRuntimeError("non-compiled function %s has an invalid value",
			                          name.c_str());
			exit(1);
			}

		return cast_intrusive<FuncVal>(v);
		}

	vector<StmtPtr> bodies;
	vector<int> priorities;

	for ( auto h : hashes )
		{
		auto cs = compiled_scripts.find(h);
		ASSERT(cs != compiled_scripts.end());

		const auto& f = cs->second;
		bodies.push_back(f.body);
		priorities.push_back(f.priority);

		// This might register the same event more than once,
		// if it's used in multiple bodies, but that's okay as
		// the semantics for Register explicitly allow it.
		for ( auto& e : f.events )
			{
			auto eh = event_registry->Register(e);
			eh->SetUsed();
			}
		}

	auto sf = make_intrusive<ScriptFunc>(std::move(name), std::move(ft), std::move(bodies),
	                                     std::move(priorities));

	return make_intrusive<FuncVal>(std::move(sf));
	}

IDPtr find_global__CPP(const char* g)
	{
	auto gl = lookup_ID(g, GLOBAL_MODULE_NAME, false, false, false);

	if ( ! gl )
		reporter->CPPRuntimeError("global %s is missing", g);

	return gl;
	}

RecordTypePtr get_record_type__CPP(const char* record_type_name)
	{
	IDPtr existing_type;

	if ( record_type_name && (existing_type = global_scope()->Find(record_type_name)) &&
	     existing_type->GetType()->Tag() == TYPE_RECORD )
		return cast_intrusive<RecordType>(existing_type->GetType());

	return make_intrusive<RecordType>(new type_decl_list());
	}

EnumTypePtr get_enum_type__CPP(const string& enum_type_name)
	{
	auto existing_type = global_scope()->Find(enum_type_name);

	if ( existing_type && existing_type->GetType()->Tag() == TYPE_ENUM )
		return cast_intrusive<EnumType>(existing_type->GetType());
	else
		return make_intrusive<EnumType>(enum_type_name);
	}

EnumValPtr make_enum__CPP(TypePtr t, zeek_int_t i)
	{
	auto et = cast_intrusive<EnumType>(std::move(t));
	return make_intrusive<EnumVal>(et, i);
	}

	} // namespace zeek::detail
