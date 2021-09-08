// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/CPP/Compile.h"


namespace zeek::detail {

using namespace std;

bool CPPCompile::CheckForCollisions()
	{
	for ( auto& g : pfs.AllGlobals() )
		{
		auto gn = string(g->Name());

		if ( hm.HasGlobal(gn) )
			{
			// Make sure the previous compilation used the
			// same type and initialization value for the global.
			auto ht_orig = hm.GlobalTypeHash(gn);
			auto hv_orig = hm.GlobalValHash(gn);

			auto ht = pfs.HashType(g->GetType());
			p_hash_type hv = 0;
			if ( g->GetVal() )
				hv = p_hash(g->GetVal());

			if ( ht != ht_orig || hv != hv_orig )
				{
				fprintf(stderr, "%s: hash clash for global %s (%llu/%llu vs. %llu/%llu)\n",
					working_dir.c_str(), gn.c_str(),
					ht, hv, ht_orig, hv_orig);
				fprintf(stderr, "val: %s\n", g->GetVal() ? obj_desc(g->GetVal().get()).c_str() : "<none>");
				return true;
				}
			}
		}

	for ( auto& t : pfs.RepTypes() )
		{
		auto tag = t->Tag();

		if ( tag != TYPE_ENUM && tag != TYPE_RECORD )
			// Other types, if inconsistent, will just not reuse
			// the previously compiled version of the type.
			continue;

		// We identify enum's and record's by name.  Make sure that
		// the name either (1) wasn't previously used, or (2) if it
		// was, it was likewise for an enum or a record.
		const auto& tn = t->GetName();
		if ( tn.empty() || ! hm.HasGlobal(tn) )
			// No concern of collision since the type name
			// wasn't previously compiled.
			continue;

		if ( tag == TYPE_ENUM && hm.HasEnumTypeGlobal(tn) )
			// No inconsistency.
			continue;

		if ( tag == TYPE_RECORD && hm.HasRecordTypeGlobal(tn) )
			// No inconsistency.
			continue;

		fprintf(stderr, "%s: type \"%s\" collides with compiled global\n",
			working_dir.c_str(), tn.c_str());
		return true;
		}

	return false;
	}

void CPPCompile::CreateGlobal(const ID* g)
	{
	auto gn = string(g->Name());
	bool is_bif = pfs.BiFGlobals().count(g) > 0;

	if ( pfs.Globals().count(g) == 0 )
		{
		// Only used in the context of calls.  If it's compilable,
		// the we'll call it directly.
		if ( compilable_funcs.count(gn) > 0 )
			{
			AddGlobal(gn, "zf", true);
			return;
			}

		if ( is_bif )
			{
			AddBiF(g, false);
			return;
			}
		}

	if ( AddGlobal(gn, "gl", true) )
		{ // We'll be creating this global.
		Emit("IDPtr %s;", globals[gn]);

		if ( pfs.Events().count(gn) > 0 )
			// This is an event that's also used as
			// a variable.
			Emit("EventHandlerPtr %s_ev;", globals[gn]);

		const auto& t = g->GetType();
		NoteInitDependency(g, TypeRep(t));

		auto exported = g->IsExport() ? "true" : "false";

		AddInit(g, globals[gn],
		        string("lookup_global__CPP(\"") + gn + "\", " +
		        GenTypeName(t) + ", " + exported + ")");
		}

	if ( is_bif )
		// This is a BiF that's referred to in a non-call context,
		// so we didn't already add it above.
		AddBiF(g, true);

	global_vars.emplace(g);
	}

void CPPCompile::UpdateGlobalHashes()
	{
	for ( auto& g : pfs.AllGlobals() )
		{
		auto gn = g->Name();

		if ( hm.HasGlobal(gn) )
			// Not new to this compilation run.
			continue;

		auto ht = pfs.HashType(g->GetType());

		p_hash_type hv = 0;
		if ( g->GetVal() )
			hv = p_hash(g->GetVal());

		fprintf(hm.HashFile(), "global\n%s\n", gn);
		fprintf(hm.HashFile(), "%llu %llu\n", ht, hv);

		// Record location information in the hash file for
		// diagnostic purposes.
		auto loc = g->GetLocationInfo();
		fprintf(hm.HashFile(), "%s %d\n", loc->filename, loc->first_line);

		// Flag any named record/enum types.
		if ( g->IsType() )
			{
			const auto& t = g->GetType();
			if ( t->Tag() == TYPE_RECORD )
				fprintf(hm.HashFile(), "record\n%s\n", gn);
			else if ( t->Tag() == TYPE_ENUM )
				fprintf(hm.HashFile(), "enum\n%s\n", gn);
			}
		}
	}

void CPPCompile::AddBiF(const ID* b, bool is_var)
	{
	auto bn = b->Name();
	auto n = string(bn);
	if ( is_var )
		n = n + "_";	// make the name distinct

	if ( AddGlobal(n, "bif", true) )
		Emit("Func* %s;", globals[n]);

	auto lookup = string("lookup_bif__CPP(\"") + bn + "\")";

	if ( standalone )
		AddActivation(globals[n] + " = " + lookup + ";");
	else
		AddInit(b, globals[n], lookup);
	}

bool CPPCompile::AddGlobal(const string& g, const char* suffix, bool track)
	{
	bool new_var = false;

	if ( globals.count(g) == 0 )
		{
		auto gn = GlobalName(g, suffix);

		if ( hm.HasGlobalVar(gn) )
			gn = scope_prefix(hm.GlobalVarScope(gn)) + gn;
		else
			{
			new_var = true;

			if ( track && update )
				fprintf(hm.HashFile(), "global-var\n%s\n%d\n",
					gn.c_str(), addl_tag);
			}

		globals.emplace(g, gn);
		}

	return new_var;
	}

void CPPCompile::RegisterEvent(string ev_name)
	{
	body_events[body_name].emplace_back(move(ev_name));
	}

const string& CPPCompile::IDNameStr(const ID* id) const
	{
	if ( id->IsGlobal() )
		{
		auto g = string(id->Name());
		ASSERT(globals.count(g) > 0);
		return ((CPPCompile*)(this))->globals[g];
		}

	ASSERT(locals.count(id) > 0);

	return ((CPPCompile*)(this))->locals[id];
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
