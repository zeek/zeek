// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::CreateGlobal(const ID* g)
	{
	auto gn = string(g->Name());
	bool is_bif = pfs.BiFGlobals().count(g) > 0;

	if ( pfs.Globals().count(g) == 0 )
		{
		// Only used in the context of calls.  If it's compilable,
		// then we'll call it directly.
		if ( compilable_funcs.count(gn) > 0 )
			{
			AddGlobal(gn, "zf");
			return;
			}

		if ( is_bif )
			{
			AddBiF(g, false);
			return;
			}
		}

	if ( AddGlobal(gn, "gl") )
		{ // We'll be creating this global.
		Emit("IDPtr %s;", globals[gn]);

		if ( pfs.Events().count(gn) > 0 )
			// This is an event that's also used as a variable.
			Emit("EventHandlerPtr %s_ev;", globals[gn]);

		auto gi = make_shared<GlobalInitInfo>(this, g, globals[gn]);
		global_id_info->AddInstance(gi);
		global_gis[g] = gi;
		}

	if ( is_bif )
		// This is a BiF that's referred to in a non-call context,
		// so we didn't already add it above.
		AddBiF(g, true);

	global_vars.emplace(g);
	}

std::shared_ptr<CPP_InitInfo> CPPCompile::RegisterGlobal(const ID* g)
	{
	auto gg = global_gis.find(g);

	if ( gg != global_gis.end() )
		return gg->second;

	auto gn = string(g->Name());

	if ( globals.count(gn) == 0 )
		{
		// Create a name for it.
		(void)IDNameStr(g);

		// That call may have created the initializer, in which
		// case no need to repeat it.
		gg = global_gis.find(g);
		if ( gg != global_gis.end() )
			return gg->second;
		}

	auto gi = make_shared<GlobalInitInfo>(this, g, globals[gn]);
	global_id_info->AddInstance(gi);
	global_gis[g] = gi;

	return gi;
	}

void CPPCompile::AddBiF(const ID* b, bool is_var)
	{
	auto bn = b->Name();
	auto n = string(bn);
	if ( is_var )
		n = n + "_"; // make the name distinct

	if ( AddGlobal(n, "bif") )
		Emit("Func* %s;", globals[n]);

	ASSERT(BiFs.count(globals[n]) == 0);
	BiFs[globals[n]] = bn;
	}

bool CPPCompile::AddGlobal(const string& g, const char* suffix)
	{
	if ( globals.count(g) > 0 )
		return false;

	globals.emplace(g, GlobalName(g, suffix));
	return true;
	}

void CPPCompile::RegisterEvent(string ev_name)
	{
	body_events[body_name].emplace_back(std::move(ev_name));
	}

const string& CPPCompile::IDNameStr(const ID* id)
	{
	if ( id->IsGlobal() )
		{
		auto g = string(id->Name());
		if ( globals.count(g) == 0 )
			CreateGlobal(id);
		return globals[g];
		}

	auto l = locals.find(id);
	ASSERT(l != locals.end());
	return l->second;
	}

string CPPCompile::LocalName(const ID* l) const
	{
	auto n = l->Name();
	auto without_module = strstr(n, "::");

	if ( without_module )
		return Canonicalize(without_module + 2);
	else
		return Canonicalize(n);
	}

string CPPCompile::Canonicalize(const char* name) const
	{
	string cname;

	for ( int i = 0; name[i]; ++i )
		{
		auto c = name[i];

		// Strip <>'s - these get introduced for lambdas.
		if ( c == '<' || c == '>' )
			continue;

		if ( c == ':' || c == '-' )
			c = '_';

		cname += c;
		}

	// Add a trailing '_' to avoid conflicts with C++ keywords.
	return cname + "_";
	}

	} // zeek::detail
