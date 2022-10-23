// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/Manager.h"

#include <cstdlib>
#include <utility>

#include "zeek/DebugLogger.h"
#include "zeek/Expr.h"
#include "zeek/util.h"
#include "zeek/zeekygen/IdentifierInfo.h"
#include "zeek/zeekygen/Info.h"
#include "zeek/zeekygen/PackageInfo.h"
#include "zeek/zeekygen/ScriptInfo.h"
#include "zeek/zeekygen/utils.h"

using namespace std;

namespace zeek::zeekygen::detail
	{

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

static void WarnMissingScript(const char* type, const zeek::detail::ID* id, const string& script)
	{
	if ( script == "<command line>" )
		return;

	DbgAndWarn(util::fmt("Can't generate Zeekygen documentation for %s %s, "
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

Manager::Manager(const string& arg_config, const string& command)
	: disabled(), comment_buffer(), comment_buffer_map(), packages(), scripts(), identifiers(),
	  all_info(), last_identifier_seen(), incomplete_type(), enum_mappings(), config(arg_config),
	  mtime()
	{
	if ( getenv("ZEEK_DISABLE_ZEEKYGEN") )
		disabled = true;

	// If running Zeek without the "-X" option, then we don't need mtime.
	if ( disabled || arg_config.empty() )
		return;

	// Find the absolute or relative path to Zeek by checking each PATH
	// component and also the current directory (so that this works if
	// command is a relative path).
	const char* env_path = getenv("PATH");
	string path = env_path ? string(env_path) + ":." : ".";
	string path_to_zeek = util::find_file(command, path);
	struct stat s;

	// One way that find_file() could fail is when Zeek is located in
	// a PATH component that starts with a tilde (such as "~/bin").  A simple
	// workaround is to just run Zeek with a relative or absolute path.
	if ( path_to_zeek.empty() || stat(path_to_zeek.c_str(), &s) < 0 )
		reporter->InternalError("Zeekygen can't get mtime of zeek binary %s (try again by "
		                        "specifying the absolute or relative path to Zeek): %s",
		                        path_to_zeek.c_str(), strerror(errno));

	// Internal error will abort above in the case that stat isn't initialized
	// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Assign)
	mtime = s.st_mtime;
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

	string name = normalize_script_path(path);

	if ( scripts.GetInfo(name) )
		{
		DbgAndWarn(util::fmt("Duplicate Zeekygen script documentation: %s", name.c_str()));
		return;
		}

	ScriptInfo* info = new ScriptInfo(name, path);
	scripts.map[name] = info;
	all_info.push_back(info);
	DBG_LOG(DBG_ZEEKYGEN, "Made ScriptInfo %s", name.c_str());

	if ( ! info->IsPkgLoader() )
		return;

	name = util::SafeDirname(name).result;

	if ( packages.GetInfo(name) )
		{
		DbgAndWarn(util::fmt("Duplicate Zeekygen package documentation: %s", name.c_str()));
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

	if ( path == "<command line>" )
		// This is a @load directive on the command line.
		return;

	if ( dep.empty() )
		{
		DbgAndWarn(util::fmt("Empty Zeekygen script doc dependency: %s", path.c_str()));
		return;
		}

	string name = normalize_script_path(path);
	string depname = normalize_script_path(dep);
	ScriptInfo* script_info = scripts.GetInfo(name);

	if ( ! script_info )
		{
		DbgAndWarn(util::fmt("Failed to add Zeekygen script doc dependency %s "
		                     "for %s",
		                     depname.c_str(), name.c_str()));
		return;
		}

	script_info->AddDependency(depname);
	DBG_LOG(DBG_ZEEKYGEN, "Added script dependency %s for %s", depname.c_str(), name.c_str());

	for ( size_t i = 0; i < comment_buffer.size(); ++i )
		DbgAndWarn(
			util::fmt("Discarded extraneous Zeekygen comment: %s", comment_buffer[i].c_str()));
	}

void Manager::ModuleUsage(const string& path, const string& module)
	{
	if ( disabled )
		return;

	if ( path == "<command line>" )
		// This is a moudle defined on the command line.
		return;

	string name = normalize_script_path(path);
	ScriptInfo* script_info = scripts.GetInfo(name);

	if ( ! script_info )
		{
		DbgAndWarn(util::fmt("Failed to add Zeekygen module usage %s in %s", module.c_str(),
		                     name.c_str()));
		return;
		}

	script_info->AddModule(module);
	DBG_LOG(DBG_ZEEKYGEN, "Added module usage %s in %s", module.c_str(), name.c_str());
	}

IdentifierInfo* Manager::CreateIdentifierInfo(zeek::detail::IDPtr id, ScriptInfo* script,
                                              bool from_redef)
	{
	const auto& id_name = id->Name();
	auto prev = identifiers.GetInfo(id_name);
	IdentifierInfo* rval = prev ? prev : new IdentifierInfo(std::move(id), script, from_redef);

	rval->AddComments(comment_buffer);
	comment_buffer.clear();

	comment_buffer_map_t::iterator it = comment_buffer_map.find(id_name);

	if ( it != comment_buffer_map.end() )
		{
		rval->AddComments(it->second);
		comment_buffer_map.erase(it);
		}

	if ( ! prev )
		{
		all_info.push_back(rval);
		identifiers.map[id_name] = rval;
		}

	last_identifier_seen = rval;

	if ( script )
		script->AddIdentifierInfo(rval);

	return rval;
	}

void Manager::StartType(zeek::detail::IDPtr id)
	{
	if ( disabled )
		return;

	if ( id->GetLocationInfo() == &zeek::detail::no_location )
		{
		DbgAndWarn(util::fmt("Can't generate zeekygen documentation for %s, "
		                     "no location available",
		                     id->Name()));
		return;
		}

	string script = normalize_script_path(id->GetLocationInfo()->filename);
	ScriptInfo* script_info = scripts.GetInfo(script);

	if ( ! script_info )
		{
		WarnMissingScript("identifier", id.get(), script);
		return;
		}

	DBG_LOG(DBG_ZEEKYGEN, "Making IdentifierInfo (incomplete) %s, in %s", id->Name(),
	        script.c_str());
	incomplete_type = CreateIdentifierInfo(std::move(id), script_info);
	}

static bool IsEnumType(zeek::detail::ID* id)
	{
	return id->IsType() ? id->GetType()->Tag() == TYPE_ENUM : false;
	}

void Manager::Identifier(zeek::detail::IDPtr id, bool from_redef)
	{
	if ( disabled )
		return;

	if ( incomplete_type )
		{
		if ( incomplete_type->Name() == id->Name() )
			{
			DBG_LOG(DBG_ZEEKYGEN, "Finished document for type %s", id->Name());
			incomplete_type->CompletedTypeDecl();
			incomplete_type = nullptr;
			return;
			}

		if ( IsEnumType(incomplete_type->GetID()) )
			enum_mappings[id->Name()] = incomplete_type->GetID()->Name();
		}

	IdentifierInfo* id_info = identifiers.GetInfo(id->Name());

	if ( id_info )
		{
		if ( IsFunc(id_info->GetID()->GetType()->Tag()) )
			{
			// Function may already been seen (declaration versus body).
			id_info->AddComments(comment_buffer);
			comment_buffer.clear();
			return;
			}

		DbgAndWarn(util::fmt("Duplicate identifier documentation: %s", id->Name()));
		return;
		}

	if ( id->GetLocationInfo() == &zeek::detail::no_location )
		{
		// Internally-created identifier (e.g. file/proto analyzer enum tags).
		// Handled specially since they don't have a script location.
		DBG_LOG(DBG_ZEEKYGEN, "Made internal IdentifierInfo %s", id->Name());
		CreateIdentifierInfo(id, nullptr, from_redef);
		return;
		}

	string script = normalize_script_path(id->GetLocationInfo()->filename);
	ScriptInfo* script_info = scripts.GetInfo(script);

	if ( ! script_info )
		{
		WarnMissingScript("identifier", id.get(), script);
		return;
		}

	DBG_LOG(DBG_ZEEKYGEN, "Making IdentifierInfo %s, in script %s", id->Name(), script.c_str());
	CreateIdentifierInfo(std::move(id), script_info, from_redef);
	}

void Manager::RecordField(const zeek::detail::ID* id, const TypeDecl* field, const string& path,
                          bool from_redef)
	{
	if ( disabled )
		return;

	IdentifierInfo* idd = identifiers.GetInfo(id->Name());

	if ( ! idd )
		{
		DbgAndWarn(util::fmt("Can't generate zeekygen documentation for "
		                     "record field %s, unknown record: %s",
		                     field->id, id->Name()));
		return;
		}

	string script = normalize_script_path(path);
	idd->AddRecordField(field, script, comment_buffer, from_redef);
	comment_buffer.clear();
	DBG_LOG(DBG_ZEEKYGEN, "Document record field %s, identifier %s, script %s", field->id,
	        id->Name(), script.c_str());
	}

void Manager::Redef(const zeek::detail::ID* id, const string& path, zeek::detail::InitClass ic,
                    zeek::detail::ExprPtr init_expr)
	{
	if ( disabled )
		return;

	if ( path == "<params>" )
		// This is a redef defined on the command line.
		return;

	IdentifierInfo* id_info = identifiers.GetInfo(id->Name());

	if ( ! id_info )
		{
		DbgAndWarn(util::fmt("Can't generate zeekygen documentation for "
		                     "redef of %s, identifier lookup failed",
		                     id->Name()));
		return;
		}

	string from_script = normalize_script_path(path);
	ScriptInfo* script_info = scripts.GetInfo(from_script);

	if ( ! script_info )
		{
		WarnMissingScript("redef", id, from_script);
		return;
		}

	id_info->AddRedef(from_script, ic, std::move(init_expr), comment_buffer);
	script_info->AddRedef(id_info);
	comment_buffer.clear();
	last_identifier_seen = id_info;
	DBG_LOG(DBG_ZEEKYGEN, "Added redef of %s from %s", id->Name(), from_script.c_str());
	}

void Manager::Redef(const zeek::detail::ID* id, const std::string& path, zeek::detail::InitClass ic)
	{
	Redef(id, path, ic, nullptr);
	}

void Manager::SummaryComment(const string& script, const string& comment)
	{
	if ( disabled )
		return;

	string name = normalize_script_path(script);
	ScriptInfo* info = scripts.GetInfo(name);

	if ( info )
		info->AddComment(RemoveLeadingSpace(comment));
	else
		DbgAndWarn(util::fmt("Lookup of script %s failed for summary comment %s", name.c_str(),
		                     comment.c_str()));
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
			DbgAndWarn(util::fmt("Discarded unassociated Zeekygen comment %s", comment.c_str()));

		return;
		}

	if ( last_identifier_seen && last_identifier_seen->Name() == id_hint )
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

	} // namespace zeek::zeekygen::detail
