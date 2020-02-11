// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"
#include "plugin/Manager.h"
#include "util.h"
#include "Info.h"
#include "PackageInfo.h"
#include "ScriptInfo.h"
#include "IdentifierInfo.h"

#include <utility>
#include <cstdlib>

using namespace zeekygen;
using namespace std;

static void DbgAndWarn(const char* msg)
	{
	if ( reporter->Errors() )
		// We've likely already reported to real source of the problem
		// as an error, avoid adding an additional warning which may
		// be confusing.
		return;

	reporter->Warning("%s", msg);
	DBG_LOG(DBG_ZEEKYGEN, "%s", msg);
	}

static void WarnMissingScript(const char* type, const ID* id,
                              const string& script)
	{
	if ( script == "<command line>" )
		return;

	DbgAndWarn(fmt("Can't generate Zeekygen doumentation for %s %s, "
	               "lookup of %s failed",
	               type, id->Name(), script.c_str()));
	}

static string RemoveLeadingSpace(const string& s)
	{
	if ( s.empty() || s[0] != ' ' )
		return s;

	// Treat "##Text" and "## Text" the same, so that a single space doesn't
	// cause reST formatting to think the later is indented a level.
	string rval = s;
	rval.erase(0, 1);
	return rval;
	}

// Turns a script's full path into a shortened, normalized version that we
// use for indexing.
static string NormalizeScriptPath(const string& path)
	{
	if ( auto p = plugin_mgr->LookupPluginByPath(path) ) 
		{
		auto rval = normalize_path(path);
		auto prefix = SafeBasename(p->PluginDirectory()).result;
		return prefix + "/" + rval.substr(p->PluginDirectory().size() + 1);
		}

	return without_bropath_component(path);
	}

Manager::Manager(const string& arg_config, const string& bro_command)
	: disabled(), comment_buffer(), comment_buffer_map(), packages(), scripts(),
	  identifiers(), all_info(), last_identifier_seen(), incomplete_type(),
	  enum_mappings(), config(arg_config), bro_mtime()
	{
	if ( zeekenv("ZEEK_DISABLE_ZEEKYGEN") )
		disabled = true;

	// If running bro without the "-X" option, then we don't need bro_mtime.
	if ( disabled || arg_config.empty() )
		return;

	// Find the absolute or relative path to bro by checking each PATH
	// component and also the current directory (so that this works if
	// bro_command is a relative path).
	const char* env_path = getenv("PATH");
	string path = env_path ? string(env_path) + ":." : ".";
	string path_to_bro = find_file(bro_command, path);
	struct stat s;

	// One way that find_file() could fail is when bro is located in
	// a PATH component that starts with a tilde (such as "~/bin").  A simple
	// workaround is to just run bro with a relative or absolute path.
	if ( path_to_bro.empty() || stat(path_to_bro.c_str(), &s) < 0 )
		reporter->InternalError("Zeekygen can't get mtime of zeek binary %s (try again by specifying the absolute or relative path to Zeek): %s",
		                        path_to_bro.c_str(), strerror(errno));

	bro_mtime = s.st_mtime;
	}

Manager::~Manager()
	{
	for ( size_t i = 0; i < all_info.size(); ++i )
		delete all_info[i];
	}

void Manager::InitPreScript()
	{
	if ( disabled )
		return;
	}

void Manager::InitPostScript()
	{
	if ( disabled )
		return;

	for ( size_t i = 0; i < all_info.size(); ++i )
		all_info[i]->InitPostScript();

	config.FindDependencies(all_info);
	}

void Manager::GenerateDocs() const
	{
	if ( disabled )
		return;

	config.GenerateDocs();
	}

void Manager::Script(const string& path)
	{
	if ( disabled )
		return;

	string name = NormalizeScriptPath(path);

	if ( scripts.GetInfo(name) )
		{
		DbgAndWarn(fmt("Duplicate Zeekygen script documentation: %s",
		               name.c_str()));
		return;
		}

	ScriptInfo* info = new ScriptInfo(name, path);
	scripts.map[name] = info;
	all_info.push_back(info);
	DBG_LOG(DBG_ZEEKYGEN, "Made ScriptInfo %s", name.c_str());

	if ( ! info->IsPkgLoader() )
		return;

	name = SafeDirname(name).result;

	if ( packages.GetInfo(name) )
		{
		DbgAndWarn(fmt("Duplicate Zeekygen package documentation: %s",
		               name.c_str()));
		return;
		}

	PackageInfo* pkginfo = new PackageInfo(name);
	packages.map[name] = pkginfo;
	all_info.push_back(pkginfo);
	DBG_LOG(DBG_ZEEKYGEN, "Made PackageInfo %s", name.c_str());
	}

void Manager::ScriptDependency(const string& path, const string& dep)
	{
	if ( disabled )
		return;

	if ( dep.empty() )
		{
		DbgAndWarn(fmt("Empty Zeekygen script doc dependency: %s",
		               path.c_str()));
		return;
		}

	string name = NormalizeScriptPath(path);
	string depname = NormalizeScriptPath(dep);
	ScriptInfo* script_info = scripts.GetInfo(name);

	if ( ! script_info )
		{
		DbgAndWarn(fmt("Failed to add Zeekygen script doc dependency %s "
		               "for %s", depname.c_str(), name.c_str()));
		return;
		}

	script_info->AddDependency(depname);
	DBG_LOG(DBG_ZEEKYGEN, "Added script dependency %s for %s",
	        depname.c_str(), name.c_str());

	for ( size_t i = 0; i < comment_buffer.size(); ++i )
		DbgAndWarn(fmt("Discarded extraneous Zeekygen comment: %s",
		               comment_buffer[i].c_str()));
	}

void Manager::ModuleUsage(const string& path, const string& module)
	{
	if ( disabled )
		return;

	string name = NormalizeScriptPath(path);
	ScriptInfo* script_info = scripts.GetInfo(name);

	if ( ! script_info )
		{
		DbgAndWarn(fmt("Failed to add Zeekygen module usage %s in %s",
		               module.c_str(), name.c_str()));
		return;
		}

	script_info->AddModule(module);
	DBG_LOG(DBG_ZEEKYGEN, "Added module usage %s in %s",
	        module.c_str(), name.c_str());
	}

IdentifierInfo* Manager::CreateIdentifierInfo(ID* id, ScriptInfo* script)
	{
	auto prev = identifiers.GetInfo(id->Name());
	IdentifierInfo* rval = prev ? prev : new IdentifierInfo(id, script);

	rval->AddComments(comment_buffer);
	comment_buffer.clear();

	comment_buffer_map_t::iterator it = comment_buffer_map.find(id->Name());

	if ( it != comment_buffer_map.end() )
		{
		rval->AddComments(it->second);
		comment_buffer_map.erase(it);
		}

	if ( ! prev )
		{
		all_info.push_back(rval);
		identifiers.map[id->Name()] = rval;
		}

	last_identifier_seen = rval;

	if ( script )
		script->AddIdentifierInfo(rval);

	return rval;
	}

void Manager::StartType(ID* id)
	{
	if ( disabled )
		return;

	if ( id->GetLocationInfo() == &no_location )
		{
		DbgAndWarn(fmt("Can't generate zeekygen doumentation for %s, "
		               "no location available", id->Name()));
		return;
		}

	string script = NormalizeScriptPath(id->GetLocationInfo()->filename);
	ScriptInfo* script_info = scripts.GetInfo(script);

	if ( ! script_info )
		{
		WarnMissingScript("identifier", id, script);
		return;
		}

	incomplete_type = CreateIdentifierInfo(id, script_info);
	DBG_LOG(DBG_ZEEKYGEN, "Made IdentifierInfo (incomplete) %s, in %s",
	        id->Name(), script.c_str());
	}

static bool IsEnumType(ID* id)
	{
	return id->AsType() ? id->AsType()->Tag() == TYPE_ENUM : false;
	}

void Manager::Identifier(ID* id)
	{
	if ( disabled )
		return;

	if ( incomplete_type )
		{
		if ( incomplete_type->Name() == id->Name() )
			{
			DBG_LOG(DBG_ZEEKYGEN, "Finished document for type %s", id->Name());
			incomplete_type->CompletedTypeDecl();
			incomplete_type = 0;
			return;
			}

		if ( IsEnumType(incomplete_type->GetID()) )
			enum_mappings[id->Name()] = incomplete_type->GetID()->Name();
		}

	IdentifierInfo* id_info = identifiers.GetInfo(id->Name());

	if ( id_info )
		{
		if ( IsFunc(id_info->GetID()->Type()->Tag()) )
			{
			// Function may already been seen (declaration versus body).
			id_info->AddComments(comment_buffer);
			comment_buffer.clear();
			return;
			}

		DbgAndWarn(fmt("Duplicate identifier documentation: %s", id->Name()));
		return;
		}

	if ( id->GetLocationInfo() == &no_location )
		{
		// Internally-created identifier (e.g. file/proto analyzer enum tags).
		// Handled specially since they don't have a script location.
		DBG_LOG(DBG_ZEEKYGEN, "Made internal IdentifierInfo %s",
		        id->Name());
		CreateIdentifierInfo(id, 0);
		return;
		}

	string script = NormalizeScriptPath(id->GetLocationInfo()->filename);
	ScriptInfo* script_info = scripts.GetInfo(script);

	if ( ! script_info )
		{
		WarnMissingScript("identifier", id, script);
		return;
		}

	CreateIdentifierInfo(id, script_info);
	DBG_LOG(DBG_ZEEKYGEN, "Made IdentifierInfo %s, in script %s",
	        id->Name(), script.c_str());
	}

void Manager::RecordField(const ID* id, const TypeDecl* field,
			  const string& path)
	{
	if ( disabled )
		return;

	IdentifierInfo* idd = identifiers.GetInfo(id->Name());

	if ( ! idd )
		{
		DbgAndWarn(fmt("Can't generate zeekygen doumentation for "
		               "record field %s, unknown record: %s",
		               field->id, id->Name()));
		return;
		}

	string script = NormalizeScriptPath(path);
	idd->AddRecordField(field, script, comment_buffer);
	comment_buffer.clear();
	DBG_LOG(DBG_ZEEKYGEN, "Document record field %s, identifier %s, script %s",
	        field->id, id->Name(), script.c_str());
	}

void Manager::Redef(const ID* id, const string& path,
                    init_class ic, Expr* init_expr)
	{
	if ( disabled )
		return;

	if ( path == "<params>" )
		// This is a redef defined on the command line.
		return;

	IdentifierInfo* id_info = identifiers.GetInfo(id->Name());

	if ( ! id_info )
		{
		DbgAndWarn(fmt("Can't generate zeekygen doumentation for "
		               "redef of %s, identifier lookup failed",
		               id->Name()));
		return;
		}

	string from_script = NormalizeScriptPath(path);
	ScriptInfo* script_info = scripts.GetInfo(from_script);

	if ( ! script_info )
		{
		WarnMissingScript("redef", id, from_script);
		return;
		}

	id_info->AddRedef(from_script, ic, init_expr, comment_buffer);
	script_info->AddRedef(id_info);
	comment_buffer.clear();
	last_identifier_seen = id_info;
	DBG_LOG(DBG_ZEEKYGEN, "Added redef of %s from %s",
	        id->Name(), from_script.c_str());
	}

void Manager::SummaryComment(const string& script, const string& comment)
	{
	if ( disabled )
		return;

	string name = NormalizeScriptPath(script);
	ScriptInfo* info = scripts.GetInfo(name);

	if ( info )
		info->AddComment(RemoveLeadingSpace(comment));
	else
		DbgAndWarn(fmt("Lookup of script %s failed for summary comment %s",
		               name.c_str(), comment.c_str()));
	}

void Manager::PreComment(const string& comment)
	{
	if ( disabled )
		return;

	comment_buffer.push_back(RemoveLeadingSpace(comment));
	}

void Manager::PostComment(const string& comment, const string& id_hint)
	{
	if ( disabled )
		return;

	if ( id_hint.empty() )
		{
		if ( last_identifier_seen )
			last_identifier_seen->AddComment(RemoveLeadingSpace(comment));
		else
			DbgAndWarn(fmt("Discarded unassociated Zeekygen comment %s",
			               comment.c_str()));

		return;
		}

	if ( last_identifier_seen &&
	     last_identifier_seen->Name() == id_hint )
		last_identifier_seen->AddComment(RemoveLeadingSpace(comment));
	else
		// Assume identifier it's associated w/ is coming later.
		comment_buffer_map[id_hint].push_back(RemoveLeadingSpace(comment));
	}

string Manager::GetEnumTypeName(const string& id) const
	{
	map<string, string>::const_iterator it = enum_mappings.find(id);
	return it == enum_mappings.end() ? "" : it->second;
	}
