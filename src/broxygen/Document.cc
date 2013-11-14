#include "Document.h"
#include "Manager.h"

#include "util.h"
#include "Val.h"
#include "Desc.h"
#include "Reporter.h"

#include <fstream>
#include <sys/stat.h>

using namespace broxygen;
using namespace std;

static bool is_public_api(const ID* id)
	{
	return (id->Scope() == SCOPE_GLOBAL) ||
	       (id->Scope() == SCOPE_MODULE && id->IsExport());
	}

static bool prettify_params(string& s)
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
			return false;
			}

		// All other characters of identifier are alphanumeric or '_'.
		if ( isalnum(next) || next == '_' )
			{
			identifier += next;
			continue;
			}

		if ( next == ':' )
			{
			if ( i + 1 < s.size() && s[i + 1] == ':' )
				{
				// It's part of an identifier's namespace scoping.
				identifier += next;
				identifier += s[i + 1];
				++i;
				continue;
				}

			// Prettify function param/return value reST markup.
			string subst;

			if ( identifier == "Returns" )
				subst = ":returns";
			else
				subst = ":param " + identifier;

			s.replace(identifier_start_pos, identifier.size(), subst);
			return true;
			}

		// Don't need to change anything.
		return false;
		}

	return false;
	}

static string make_heading(const string& heading, char underline)
	{
	return heading + "\n" + string(heading.size(), underline) + "\n";
	}

PackageDocument::PackageDocument(const string& arg_name)
    : Document(),
      pkg_name(arg_name), readme()
	{
	string readme_file = find_file(pkg_name + "/README", bro_path());

	if ( readme_file.empty() )
		return;

	ifstream f(readme_file.c_str());

	if ( ! f.is_open() )
		reporter->InternalWarning("Broxygen failed to open '%s': %s",
		                          readme_file.c_str(), strerror(errno));

	string line;

	while ( getline(f, line) )
		readme.push_back(line);

	if ( f.bad() )
		reporter->InternalWarning("Broxygen error reading '%s': %s",
		                          readme_file.c_str(), strerror(errno));
	}

string PackageDocument::DoReStructuredText(bool roles_only) const
	{
	string rval = fmt(":doc:`%s <%s/index>`\n\n", pkg_name.c_str(),
	                  pkg_name.c_str());

	for ( size_t i = 0; i < readme.size(); ++i )
		rval += "   " + readme[i] + "\n";

	return rval;
	}

IdentifierDocument::IdentifierDocument(ID* arg_id, ScriptDocument* script)
    : Document(),
      comments(), id(arg_id), initial_val_desc(), redefs(), fields(),
      last_field_seen(), declaring_script(script)
	{
	Ref(id);

	if ( id->ID_Val() )
		{
		ODesc d;
		id->ID_Val()->Describe(&d);
		initial_val_desc = d.Description();
		}
	}

IdentifierDocument::~IdentifierDocument()
	{
	Unref(id);

	for ( redef_list::const_iterator it = redefs.begin(); it != redefs.end();
	      ++it )
		delete *it;

	for ( record_field_map::const_iterator it = fields.begin();
	      it != fields.end(); ++it )
		delete it->second;
	}

void IdentifierDocument::AddRedef(const string& script,
                                  const vector<string>& comments)
	{
	Redefinition* redef = new Redefinition();
	redef->from_script = script;

	if ( id->ID_Val() )
		{
		ODesc d;
		id->ID_Val()->Describe(&d);
		redef->new_val_desc = d.Description();
		}

	redef->comments = comments;
	redefs.push_back(redef);
	}

void IdentifierDocument::AddRecordField(const TypeDecl* field,
                                        const string& script,
                                        vector<string>& comments)
	{
	RecordField* rf = new RecordField();
	rf->field = new TypeDecl(*field);
	rf->from_script = script;
	rf->comments = comments;
	fields[rf->field->id] = rf;
	last_field_seen = rf;
	}

vector<string> IdentifierDocument::GetComments() const
	{
	return comments;
	}

vector<string> IdentifierDocument::GetFieldComments(const string& field) const
	{
	record_field_map::const_iterator it = fields.find(field);

	if ( it == fields.end() )
		return vector<string>();

	return it->second->comments;
	}

list<IdentifierDocument::Redefinition>
IdentifierDocument::GetRedefs(const string& from_script) const
	{
	list<Redefinition> rval;

	for ( redef_list::const_iterator it = redefs.begin(); it != redefs.end();
	      ++it )
		{
		if ( from_script == (*it)->from_script )
			rval.push_back(*(*it));
		}

	return rval;
	}

string IdentifierDocument::GetDeclaringScriptForField(const string& field) const
	{
	record_field_map::const_iterator it = fields.find(field);

	if ( it == fields.end() )
		return "";

	return it->second->from_script;
	}

string IdentifierDocument::DoReStructuredText(bool roles_only) const
	{
	ODesc d;
	d.SetIndentSpaces(3);
	d.SetQuotes(true);
	id->DescribeReST(&d, roles_only);

	if ( comments.empty() )
		return d.Description();

	d.ClearIndentLevel();
	d.PushIndent();

	for ( size_t i = 0; i < comments.size(); ++i )
		{
		if ( i > 0 )
			d.NL();

		if ( IsFunc(id->Type()->Tag()) )
			{
			string s = comments[i];

			if ( prettify_params(s) )
				d.NL();

			d.Add(s.c_str());
			}
		else
			d.Add(comments[i].c_str());
		}

	return d.Description();
	}

ScriptDocument::ScriptDocument(const string& arg_name, const string& arg_path)
    : Document(),
      name(arg_name), path(arg_path),
      is_pkg_loader(SafeBasename(name).result == PACKAGE_LOADER),
      dependencies(), module_usages(), comments(), identifier_docs(),
      options(), constants(), state_vars(), types(), events(), hooks(),
      functions(), redefs()
	{
	}

void ScriptDocument::AddIdentifierDoc(IdentifierDocument* doc)
	{
	identifier_docs[doc->Name()] = doc;
	}

void ScriptDocument::DoInitPostScript()
	{
	for ( id_doc_map::const_iterator it = identifier_docs.begin();
	      it != identifier_docs.end(); ++it )
		{
		IdentifierDocument* doc = it->second;
		ID* id = doc->GetID();

		if ( ! is_public_api(id) )
			continue;

		if ( id->AsType() )
			{
			types.push_back(doc);
			DBG_LOG(DBG_BROXYGEN, "Filter id '%s' in '%s' as a type",
			        id->Name(), name.c_str());
			continue;
			}

		if ( IsFunc(id->Type()->Tag()) )
			{
			switch ( id->Type()->AsFuncType()->Flavor() ) {
			case FUNC_FLAVOR_HOOK:
				DBG_LOG(DBG_BROXYGEN, "Filter id '%s' in '%s' as a hook",
				        id->Name(), name.c_str());
				hooks.push_back(doc);
				break;
			case FUNC_FLAVOR_EVENT:
				DBG_LOG(DBG_BROXYGEN, "Filter id '%s' in '%s' as a event",
				        id->Name(), name.c_str());
				events.push_back(doc);
				break;
			case FUNC_FLAVOR_FUNCTION:
				DBG_LOG(DBG_BROXYGEN, "Filter id '%s' in '%s' as a function",
				        id->Name(), name.c_str());
				functions.push_back(doc);
				break;
			default:
				reporter->InternalError("Invalid function flavor");
				break;
			}

			continue;
			}

		if ( id->IsConst() )
			{
			if ( id->FindAttr(ATTR_REDEF) )
				{
				DBG_LOG(DBG_BROXYGEN, "Filter id '%s' in '%s' as an option",
				        id->Name(), name.c_str());
				options.push_back(doc);
				}
			else
				{
				DBG_LOG(DBG_BROXYGEN, "Filter id '%s' in '%s' as a constant",
				        id->Name(), name.c_str());
				constants.push_back(doc);
				}

			continue;
			}

		if ( id->Type()->Tag() == TYPE_ENUM )
			// Enums are always referenced/documented from the type's
			// documentation.
			continue;

		DBG_LOG(DBG_BROXYGEN, "Filter id '%s' in '%s' as a state variable",
		        id->Name(), name.c_str());
		state_vars.push_back(doc);
		}
	}

vector<string> ScriptDocument::GetComments() const
	{
	return comments;
	}

static size_t end_of_first_sentence(const string& s)
	{
	size_t rval = 0;

	while ( (rval = s.find_first_of('.', rval)) != string::npos )
		{
		if ( rval == s.size() - 1 )
			// Period is at end of string.
			return rval;

		if ( isspace(s[rval + 1]) )
			// Period has a space after it.
			return rval;

		// Period has some non-space character after it, keep looking.
		++rval;
		}

	return rval;
	}

static bool is_all_whitespace(const string& s)
	{
	for ( size_t i = 0; i < s.size(); ++i )
		if ( ! isspace(s[i]) )
			return false;

	return true;
	}

static vector<string> summary_comment(const vector<string>& cmnts)
	{
	vector<string> rval;

	for ( size_t i = 0; i < cmnts.size(); ++i )
		{
		size_t end = end_of_first_sentence(cmnts[i]);

		if ( end == string::npos )
			{
			if ( is_all_whitespace(cmnts[i]) )
				break;

			rval.push_back(cmnts[i]);
			}
		else
			{
			rval.push_back(cmnts[i].substr(0, end + 1));
			break;
			}
		}

	return rval;
	}

class ReStructuredTextTable {
public:

	ReStructuredTextTable(size_t arg_num_cols)
		: num_cols(arg_num_cols), rows(), longest_row_in_column()
		{
		for ( size_t i = 0; i < num_cols; ++i )
			longest_row_in_column.push_back(1);
		}

	void AddRow(const vector<string>& new_row)
		{
		assert(new_row.size() == num_cols);
		rows.push_back(new_row);

		for ( size_t i = 0; i < new_row.size(); ++i )
			if ( new_row[i].size() > longest_row_in_column[i] )
				longest_row_in_column[i] = new_row[i].size();
		}

	static string MakeBorder(const vector<size_t> col_sizes, char border)
		{
		string rval;

		for ( size_t i = 0; i < col_sizes.size(); ++i )
			{
			if ( i > 0 )
				rval += " ";

			rval += string(col_sizes[i], border);
			}

		rval += "\n";
		return rval;
		}

	string AsString(char border) const
		{
		string rval = MakeBorder(longest_row_in_column, border);

		for ( size_t row = 0; row < rows.size(); ++row )
			{
			for ( size_t col = 0; col < num_cols; ++col )
				{
				if ( col > 0 )
					{
					size_t last = rows[row][col - 1].size();
					size_t longest = longest_row_in_column[col - 1];
					size_t whitespace = longest - last + 1;
					rval += string(whitespace, ' ');
					}

				rval += rows[row][col];
				}

			rval += "\n";
			}

		rval += MakeBorder(longest_row_in_column, border);
		return rval;
		}


private:

	size_t num_cols;
	vector<vector<string> > rows;
	vector<size_t> longest_row_in_column;
};

static void add_summary_rows(const ODesc& id_desc, const vector<string>& cmnts,
                             ReStructuredTextTable* table)
	{
	vector<string> row;
	row.push_back(id_desc.Description());

	if ( cmnts.empty() )
		{
		row.push_back("");
		table->AddRow(row);
		return;
		}

	row.push_back(cmnts[0]);
	table->AddRow(row);

	for ( size_t i = 1; i < cmnts.size(); ++i )
		{
		row.clear();
		row.push_back("");
		row.push_back(cmnts[i]);
		table->AddRow(row);
		}
	}

static string make_summary(const string& heading, char underline, char border,
                           const list<IdentifierDocument*>& id_list)
	{
	if ( id_list.empty() )
		return "";

	ReStructuredTextTable table(2);

	for ( list<IdentifierDocument*>::const_iterator it = id_list.begin();
	      it != id_list.end(); ++it )
		{
		ID* id = (*it)->GetID();
		ODesc d;
		d.SetQuotes(1);
		id->DescribeReSTShort(&d);
		add_summary_rows(d, summary_comment((*it)->GetComments()), &table);
		}

	return make_heading(heading, underline) + table.AsString(border) + "\n";
	}

static string make_redef_summary(const string& heading, char underline,
                                 char border, const string& from_script,
                                 const set<IdentifierDocument*>& id_set)
	{
	if ( id_set.empty() )
		return "";

	ReStructuredTextTable table(2);

	for ( set<IdentifierDocument*>::const_iterator it = id_set.begin();
	      it != id_set.end(); ++it )
		{
		ID* id = (*it)->GetID();
		ODesc d;
		d.SetQuotes(1);
		id->DescribeReSTShort(&d);

		typedef list<IdentifierDocument::Redefinition> redef_list;
		redef_list redefs = (*it)->GetRedefs(from_script);

		for ( redef_list::const_iterator iit = redefs.begin();
		      iit != redefs.end(); ++iit )
			add_summary_rows(d, summary_comment(iit->comments), &table);
		}

	return make_heading(heading, underline) + table.AsString(border) + "\n";
	}

static string make_details(const string& heading, char underline,
                           const list<IdentifierDocument*>& id_list)
	{
	if ( id_list.empty() )
		return "";

	string rval = make_heading(heading, underline);

	for ( list<IdentifierDocument*>::const_iterator it = id_list.begin();
	      it != id_list.end(); ++it )
		{
		rval += (*it)->ReStructuredText();
		rval += "\n\n";
		}

	return rval;
	}

static string make_redef_details(const string& heading, char underline,
                                 const set<IdentifierDocument*>& id_set)
	{
	if ( id_set.empty() )
		return "";

	string rval = make_heading(heading, underline);

	for ( set<IdentifierDocument*>::const_iterator it = id_set.begin();
	      it != id_set.end(); ++it )
		{
		rval += (*it)->ReStructuredText(true);
		rval += "\n\n";
		}

	return rval;
	}

string ScriptDocument::DoReStructuredText(bool roles_only) const
	{
	string rval;

	rval += ":tocdepth: 3\n\n";
	rval += make_heading(name, '=');

	for ( string_set::const_iterator it = module_usages.begin();
	      it != module_usages.end(); ++it )
		rval += ".. bro:namespace:: " + *it + "\n";

	rval += "\n";

	for ( size_t i = 0; i < comments.size(); ++i )
		rval += comments[i] + "\n";

	rval += "\n";

	if ( ! module_usages.empty() )
		{
		rval += module_usages.size() > 1 ? ":Namespaces: " : ":Namespace: ";

		for ( string_set::const_iterator it = module_usages.begin();
		      it != module_usages.end(); ++it )
			{
			if ( it != module_usages.begin() )
				rval += ", ";

			rval += *it;
			}

		rval += "\n";
		}

	if ( ! dependencies.empty() )
		{
		rval += ":Imports: ";

		for ( string_set::const_iterator it = dependencies.begin();
		      it != dependencies.end(); ++it )
			{
			if ( it != dependencies.begin() )
				rval += ", ";

			rval += fmt(":doc:`%s </scripts/%s>`", it->c_str(), it->c_str());
			// TODO linking to packages is a bit different?
			}

		rval += "\n";
		}

	// TODO: make this an absolute path?
	rval += fmt(":Source File: :download:`%s`\n", name.c_str());
	rval += "\n";
	rval += make_heading("Summary", '~');
	rval += make_summary("Options", '#', '=', options);
	rval += make_summary("Constants", '#', '=', constants);
	rval += make_summary("State Variables", '#', '=', state_vars);
	rval += make_summary("Types", '#', '=', types);
	rval += make_redef_summary("Redefinitions", '#', '=', name, redefs);
	rval += make_summary("Events", '#', '=', events);
	rval += make_summary("Hooks", '#', '=', hooks);
	rval += make_summary("Functions", '#', '=', functions);
	rval += "\n";
	rval += make_heading("Detailed Interface", '~');
	rval += make_details("Options", '#', options);
	rval += make_details("Constants", '#', constants);
	rval += make_details("State Variables", '#', state_vars);
	rval += make_details("Types", '#', types);
	//rval += make_redef_details("Redefinitions", '#', redefs);
	rval += make_details("Events", '#', events);
	rval += make_details("Hooks", '#', hooks);
	rval += make_details("Functions", '#', functions);

	return rval;
	}

static time_t get_mtime(const string& filename)
	{
	struct stat s;

	if ( stat(filename.c_str(), &s) < 0 )
		reporter->InternalError("Broxygen failed to stat file '%s': %s",
		                        filename.c_str(), strerror(errno));

	return s.st_mtime;
	}

time_t IdentifierDocument::DoGetModificationTime() const
	{
	// Could probably get away with just checking the set of scripts that
	// contributed to the ID declaration/redefinitions, but this is easier...
	return declaring_script->GetModificationTime();
	}

time_t ScriptDocument::DoGetModificationTime() const
	{
	time_t most_recent = get_mtime(path);

	for ( string_set::const_iterator it = dependencies.begin();
	      it != dependencies.end(); ++it )
		{
		Document* doc = broxygen_mgr->GetScriptDoc(*it);

		if ( ! doc )
			{
			string pkg_name = *it + "/" + PACKAGE_LOADER;
			doc = broxygen_mgr->GetScriptDoc(pkg_name);

			if ( ! doc )
				reporter->InternalWarning("Broxygen failed to get mtime of %s",
				                          it->c_str());
			continue;
			}

		time_t dep_mtime = doc->GetModificationTime();

		if ( dep_mtime > most_recent )
			most_recent = dep_mtime;
		}

	return most_recent;
	}

time_t PackageDocument::DoGetModificationTime() const
	{
	string readme_file = find_file(pkg_name + "/README", bro_path());

	if ( readme_file.empty() )
		return 0;

	return get_mtime(readme_file);
	}
