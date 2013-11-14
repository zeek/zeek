#include "Manager.h"
#include "util.h"

#include <utility>
#include <cstdlib>

using namespace broxygen;
using namespace std;

static void DbgAndWarn(const char* msg)
	{
	reporter->InternalWarning("%s", msg);
	DBG_LOG(DBG_BROXYGEN, "%s", msg);
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

Manager::Manager(const string& arg_config, const string& bro_command)
    : disabled(), comment_buffer(), comment_buffer_map(), packages(), scripts(),
      identifiers(), all_docs(), last_identifier_seen(), incomplete_type(),
      enum_mappings(), config(arg_config), bro_mtime()
	{
	if ( getenv("BRO_DISABLE_BROXYGEN") )
		disabled = true;

	string path_to_bro = find_file(bro_command, getenv("PATH"));
	struct stat s;

	if ( path_to_bro.empty() || stat(path_to_bro.c_str(), &s) < 0 )
		reporter->InternalError("Broxygen can't get mtime of bro binary %s: %s",
		                        path_to_bro.c_str(), strerror(errno));

	bro_mtime = s.st_mtime;
	}

Manager::~Manager()
	{
	for ( size_t i = 0; i < all_docs.size(); ++i )
		delete all_docs[i];
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

	for ( size_t i = 0; i < all_docs.size(); ++i )
		all_docs[i]->InitPostScript();

	config.FindDependencies(all_docs);
	}

void Manager::GenerateDocs() const
	{
	if ( disabled )
		return;

	config.GenerateDocs();
	}

void Manager::File(const string& path)
	{
	if ( disabled )
		return;

	string name = without_bropath_component(path);

	if ( scripts.GetDocument(name) )
		{
		DbgAndWarn(fmt("Duplicate script documentation: %s", name.c_str()));
		return;
		}

	ScriptDocument* doc = new ScriptDocument(name, path);
	scripts.map[name] = doc;
	all_docs.push_back(doc);
	DBG_LOG(DBG_BROXYGEN, "Made ScriptDocument %s", name.c_str());

	if ( ! doc->IsPkgLoader() )
		return;

	name = SafeDirname(name).result;

	if ( packages.GetDocument(name) )
		{
		DbgAndWarn(fmt("Duplicate package documentation: %s", name.c_str()));
		return;
		}

	PackageDocument* pkgdoc = new PackageDocument(name);
	packages.map[name] = pkgdoc;
	all_docs.push_back(pkgdoc);
	DBG_LOG(DBG_BROXYGEN, "Made PackageDocument %s", name.c_str());
	}

void Manager::ScriptDependency(const string& path, const string& dep)
	{
	if ( disabled )
		return;

	if ( dep.empty() )
		{
		DbgAndWarn(fmt("Empty script doc dependency: %s", path.c_str()));
		return;
		}

	string name = without_bropath_component(path);
	string depname = without_bropath_component(dep);
	ScriptDocument* script_doc = scripts.GetDocument(name);

	if ( ! script_doc )
		{
		DbgAndWarn(fmt("Failed to add script doc dependency %s for %s",
		               depname.c_str(), name.c_str()));
		return;
		}

	script_doc->AddDependency(depname);
	DBG_LOG(DBG_BROXYGEN, "Added script dependency %s for %s",
	        depname.c_str(), name.c_str());

	for ( size_t i = 0; i < comment_buffer.size(); ++i )
		DbgAndWarn(fmt("Discarded extraneous Broxygen comment: %s",
		               comment_buffer[i].c_str()));
	}

void Manager::ModuleUsage(const string& path, const string& module)
	{
	if ( disabled )
		return;

	string name = without_bropath_component(path);
	ScriptDocument* script_doc = scripts.GetDocument(name);

	if ( ! script_doc )
		{
		DbgAndWarn(fmt("Failed to add module usage %s in %s",
		               module.c_str(), name.c_str()));
		return;
		}

	script_doc->AddModule(module);
	DBG_LOG(DBG_BROXYGEN, "Added module usage %s in %s",
	        module.c_str(), name.c_str());
	}

IdentifierDocument* Manager::CreateIdentifierDoc(ID* id, ScriptDocument* script)
	{
	IdentifierDocument* rval = new IdentifierDocument(id, script);

	rval->AddComments(comment_buffer);
	comment_buffer.clear();

	comment_buffer_map_t::const_iterator it =
	        comment_buffer_map.find(id->Name());

	if ( it != comment_buffer_map.end() )
		{
		rval->AddComments(it->second);
		comment_buffer_map.erase(it);
		}

	all_docs.push_back(rval);
	identifiers.map[id->Name()] = rval;
	last_identifier_seen = rval;

	if ( script )
		script->AddIdentifierDoc(rval);

	return rval;
	}

void Manager::StartType(ID* id)
	{
	if ( disabled )
		return;

	if ( id->GetLocationInfo() == &no_location )
		{
		DbgAndWarn(fmt("Can't document %s, no location available", id->Name()));
		return;
		}

	string script = without_bropath_component(id->GetLocationInfo()->filename);
	ScriptDocument* script_doc = scripts.GetDocument(script);

	if ( ! script_doc )
		{
		DbgAndWarn(fmt("Can't document identifier %s, lookup of %s failed",
		               id->Name(), script.c_str()));
		return;
		}

	incomplete_type = CreateIdentifierDoc(id, script_doc);
	DBG_LOG(DBG_BROXYGEN, "Made IdentifierDocument (incomplete) %s, in %s",
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
			DBG_LOG(DBG_BROXYGEN, "Finished document for type %s", id->Name());
			incomplete_type->CompletedTypeDecl();
			incomplete_type = 0;
			return;
			}

		if ( IsEnumType(incomplete_type->GetID()) )
			enum_mappings[id->Name()] = incomplete_type->GetID()->Name();
		}

	IdentifierDocument* id_doc = identifiers.GetDocument(id->Name());

	if ( id_doc )
		{
		if ( IsFunc(id_doc->GetID()->Type()->Tag()) )
			{
			// Function may already been seen (declaration versus body).
			id_doc->AddComments(comment_buffer);
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
		DBG_LOG(DBG_BROXYGEN, "Made internal IdentifierDocument %s",
		        id->Name());
		CreateIdentifierDoc(id, 0);
		return;
		}

	string script = without_bropath_component(id->GetLocationInfo()->filename);
	ScriptDocument* script_doc = scripts.GetDocument(script);

	if ( ! script_doc )
		{
		DbgAndWarn(fmt("Can't document identifier %s, lookup of %s failed",
		               id->Name(), script.c_str()));
		return;
		}

	CreateIdentifierDoc(id, script_doc);
	DBG_LOG(DBG_BROXYGEN, "Made IdentifierDocument %s, in script %s",
	        id->Name(), script.c_str());
	}

void Manager::RecordField(const ID* id, const TypeDecl* field,
                          const string& path)
	{
	if ( disabled )
		return;

	IdentifierDocument* idd = identifiers.GetDocument(id->Name());

	if ( ! idd )
		{
		DbgAndWarn(fmt("Can't document record field %s, unknown record: %s",
		               field->id, id->Name()));
		return;
		}

	string script = without_bropath_component(path);
	idd->AddRecordField(field, script, comment_buffer);
	comment_buffer.clear();
	DBG_LOG(DBG_BROXYGEN, "Document record field %s, identifier %s, script %s",
	        field->id, id->Name(), script.c_str());
	}

void Manager::Redef(const ID* id, const string& path)
	{
	if ( disabled )
		return;

	if ( path == "<params>" )
		// This is a redef defined on the command line.
		return;

	IdentifierDocument* id_doc = identifiers.GetDocument(id->Name());

	if ( ! id_doc )
		{
		DbgAndWarn(fmt("Can't document redef of %s, identifier lookup failed",
		               id->Name()));
		return;
		}

	string from_script = without_bropath_component(path);
	ScriptDocument* script_doc = scripts.GetDocument(from_script);

	if ( ! script_doc )
		{
		DbgAndWarn(fmt("Can't document redef of %s, lookup of %s failed",
		               id->Name(), from_script.c_str()));
		return;
		}

	id_doc->AddRedef(from_script, comment_buffer);
	script_doc->AddRedef(id_doc);
	comment_buffer.clear();
	last_identifier_seen = id_doc;
	DBG_LOG(DBG_BROXYGEN, "Added redef of %s from %s",
	        id->Name(), from_script.c_str());
	}

void Manager::SummaryComment(const string& script, const string& comment)
	{
	if ( disabled )
		return;

	string name = without_bropath_component(script);
	ScriptDocument* doc = scripts.GetDocument(name);

	if ( doc )
		doc->AddComment(RemoveLeadingSpace(comment));
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
			DbgAndWarn(fmt("Discarded unassociated Broxygen comment %s",
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
