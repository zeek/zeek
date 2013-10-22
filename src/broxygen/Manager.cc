#include "Manager.h"
#include "Reporter.h"
#include "util.h"

#include <utility>

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

static string PrettifyParams(const string& s)
	{
	size_t identifier_start_pos = 0;
	bool in_identifier = false;
	string identifier;

	for ( size_t i = 0; i < s.size(); ++i )
		{
		char next = s[i];

		if ( ! in_identifier )
			{
			// Pass by leading whitespace.
			if ( isspace(next) )
				continue;

			// Only allow alphabetic and '_' as first char of identifier.
			if ( isalpha(next) || next == '_' )
				{
				identifier_start_pos = i;
				identifier += next;
				in_identifier = true;
				continue;
				}

			// Don't need to change anything.
			return s;
			}

		// All other character of identifier are alphanumeric or '_'.
		if ( isalnum(next) || next == '_' )
			{
			identifier += next;
			continue;
			}

		// Prettify param and return value docs for a function's reST markup.
		if ( next == ':' )
			{
			string rval = s;
			string subst;

			if ( identifier == "Returns" )
				subst = "\n:returns";
			else
				subst = "\n:param " + identifier;

			rval.replace(identifier_start_pos, identifier.size(), subst);
			return rval;
			}

		// Don't need to change anything.
		return s;
		}

	return s;
	}

Manager::Manager(const string& config)
    : disabled(), comment_buffer(), packages(), scripts(), identifiers(),
      all_docs(), last_doc_seen(), incomplete_type()
	{
	if ( getenv("BRO_DISABLE_BROXYGEN") )
		disabled = true;
	// TODO config file stuff
	}

Manager::~Manager()
	{
	for ( DocSet::const_iterator it = all_docs.begin(); it != all_docs.end();
	      ++it )
		delete *it;
	}

void Manager::InitPreScript()
	{
	if ( disabled )
		return;
	// TODO: create file/proto analyzer doc
	}

void Manager::InitPostScript()
	{
	if ( disabled )
		return;
	// TODO: dependency resolution stuff?
	}

void Manager::GenerateDocs() const
	{
	if ( disabled )
		return;
	// TODO

	// may be a no-op if no config file
	}

void Manager::File(const string& path)
	{
	if ( disabled )
		return;

	string name = without_bropath_component(path);

	if ( scripts.find(name) != scripts.end() )
		{
		DbgAndWarn(fmt("Duplicate script documentation: %s", name.c_str()));
		return;
		}

	ScriptDocument* doc = new ScriptDocument(name);
	scripts[name] = doc;
	RegisterDoc(doc);
	DBG_LOG(DBG_BROXYGEN, "Made ScriptDocument %s", name.c_str());

	if ( ! doc->IsPkgLoader() )
		return;

	if ( packages.find(name) != packages.end() )
		{
		DbgAndWarn(fmt("Duplicate package documentation: %s", name.c_str()));
		return;
		}

	packages[name] = new PackageDocument(name);
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
	ScriptMap::const_iterator it = scripts.find(name);

	if ( it == scripts.end() )
		{
		DbgAndWarn(fmt("Failed to add script doc dependency %s for %s",
		               depname.c_str(), name.c_str()));
		return;
		}

	it->second->AddDependency(depname);
	DBG_LOG(DBG_BROXYGEN, "Added script dependency %s for %s",
	        depname.c_str(), name.c_str());

	for ( CommentBuffer::const_iterator it = comment_buffer.begin();
	      it != comment_buffer.end(); ++it )
		DbgAndWarn(fmt("Discarded extraneous Broxygen comment: %s",
		               it->c_str()));
	}

void Manager::ModuleUsage(const string& path, const string& module)
	{
	if ( disabled )
		return;

	string name = without_bropath_component(path);
	ScriptMap::const_iterator it = scripts.find(name);

	if ( it == scripts.end() )
		{
		DbgAndWarn(fmt("Failed to add module usage %s in %s",
		               module.c_str(), name.c_str()));
		return;
		}

	DBG_LOG(DBG_BROXYGEN, "Added module usage %s in %s",
	        module.c_str(), name.c_str());
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
	ScriptMap::const_iterator sit = scripts.find(script);

	if ( sit == scripts.end() )
		{
		DbgAndWarn(fmt("Can't document identifier %s, lookup of %s failed",
		               id->Name(), script.c_str()));
		return;
		}

	IdentifierDocument* doc = new IdentifierDocument(id);
	doc->AddComments(comment_buffer);
	comment_buffer.clear();
	identifiers[id->Name()] = doc;
	RegisterDoc(doc);
	sit->second->AddIdentifierDoc(doc);
	incomplete_type = doc;
	DBG_LOG(DBG_BROXYGEN, "Made IdentifierDocument (incomplete) %s, in %s",
	        id->Name(), script.c_str());
	}

void Manager::Identifier(ID* id)
	{
	if ( disabled )
		return;

	if ( incomplete_type && incomplete_type->Name() == id->Name() )
		{
		DBG_LOG(DBG_BROXYGEN, "Finished document for type %s", id->Name());
		incomplete_type = 0;
		return;
		}

	if ( id->GetLocationInfo() == &no_location )
		{
		// Internally-created identifier (e.g. file/proto analyzer enum tags).
		// Can be ignored here as they need to be documented via other means.
		DBG_LOG(DBG_BROXYGEN, "Skip documenting identifier %s: no location",
		        id->Name());
		return;
		}

	IdentifierMap::const_iterator iit = identifiers.find(id->Name());

	if ( iit != identifiers.end() )
		{
		if ( IsFunc(iit->second->GetID()->Type()->Tag()) )
			{
			// Function may already been seen (declaration versus body).
			iit->second->AddComments(comment_buffer);
			comment_buffer.clear();
			return;
			}

		DbgAndWarn(fmt("Duplicate identifier documentation: %s", id->Name()));
		return;
		}

	string script = without_bropath_component(id->GetLocationInfo()->filename);
	ScriptMap::const_iterator sit = scripts.find(script);

	if ( sit == scripts.end() )
		{
		DbgAndWarn(fmt("Can't document identifier %s, lookup of %s failed",
		               id->Name(), script.c_str()));
		return;
		}

	IdentifierDocument* doc = new IdentifierDocument(id);
	doc->AddComments(comment_buffer);
	comment_buffer.clear();
	identifiers[id->Name()] = doc;
	RegisterDoc(doc);
	sit->second->AddIdentifierDoc(doc);
	DBG_LOG(DBG_BROXYGEN, "Made IdentifierDocument %s, in script %s",
	        id->Name(), script.c_str());
	}

void Manager::RecordField(const ID* id, const TypeDecl* field,
                          const string& path)
	{
	if ( disabled )
		return;

	IdentifierDocument* idd = 0;

	if ( incomplete_type )
		{
		if ( incomplete_type->Name() != id->Name() )
			{
			DbgAndWarn(fmt("Can't document record field %s in record %s, "
			               "expected record %s", field->id, id->Name(),
			               incomplete_type->Name().c_str()));
			return;
			}

		idd = incomplete_type;
		}
	else
		{
		IdentifierMap::const_iterator it = identifiers.find(id->Name());

		if ( it == identifiers.end() )
			{
			DbgAndWarn(fmt("Can't document record field %s, unknown record: %s",
			               field->id, id->Name()));
			return;
			}

		idd = it->second;
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

	IdentifierMap::const_iterator iit = identifiers.find(id->Name());

	if ( iit == identifiers.end() )
		{
		DbgAndWarn(fmt("Can't document redef of %s, identifier lookup failed",
		               id->Name()));
		return;
		}

	string from_script = without_bropath_component(path);
	ScriptMap::const_iterator sit = scripts.find(from_script);

	if ( sit == scripts.end() )
		{
		DbgAndWarn(fmt("Can't document redef of %s, lookup of %s failed",
		               id->Name(), from_script.c_str()));
		return;
		}

	iit->second->AddRedef(from_script, comment_buffer);
	comment_buffer.clear();
	DBG_LOG(DBG_BROXYGEN, "Added redef of %s to %s",
	        id->Name(), from_script.c_str());
	}

void Manager::SummaryComment(const string& script, const string& comment)
	{
	if ( disabled )
		return;

	string name = without_bropath_component(script);
	ScriptMap::const_iterator it = scripts.find(name);

	if ( it == scripts.end() )
		{
		DbgAndWarn(fmt("Lookup of script %s failed for summary comment %s",
		               name.c_str(), comment.c_str()));
		return;
		}

	it->second->AddComment(RemoveLeadingSpace(comment));
	}

void Manager::PreComment(const string& comment)
	{
	if ( disabled )
		return;

	comment_buffer.push_back(PrettifyParams(RemoveLeadingSpace(comment)));
	}

void Manager::PostComment(const string& comment)
	{
	if ( disabled )
		return;

	IdentifierDocument* doc = dynamic_cast<IdentifierDocument*>(last_doc_seen);

	if ( ! doc )
		{
		DbgAndWarn(fmt("Discarded comment not associated w/ an identifier %s",
		               comment.c_str()));
		return;
		}

	doc->AddComment(RemoveLeadingSpace(comment));
	}

void Manager::RegisterDoc(Document* d)
	{
	if ( ! d )
		return;

	all_docs.insert(d);
	last_doc_seen = d;
	}
