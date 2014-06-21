// See the file "COPYING" in the main distribution directory for copyright.

#include "IdentifierInfo.h"
#include "utils.h"

#include "Desc.h"
#include "Val.h"

using namespace std;
using namespace broxygen;

IdentifierInfo::IdentifierInfo(ID* arg_id, ScriptInfo* script)
	: Info(),
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

IdentifierInfo::~IdentifierInfo()
	{
	Unref(id);

	for ( redef_list::const_iterator it = redefs.begin(); it != redefs.end();
	      ++it )
		delete *it;

	for ( record_field_map::const_iterator it = fields.begin();
	      it != fields.end(); ++it )
		delete it->second;
	}

void IdentifierInfo::AddRedef(const string& script,
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

void IdentifierInfo::AddRecordField(const TypeDecl* field,
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

vector<string> IdentifierInfo::GetComments() const
	{
	return comments;
	}

vector<string> IdentifierInfo::GetFieldComments(const string& field) const
	{
	record_field_map::const_iterator it = fields.find(field);

	if ( it == fields.end() )
		return vector<string>();

	return it->second->comments;
	}

list<IdentifierInfo::Redefinition>
IdentifierInfo::GetRedefs(const string& from_script) const
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

string IdentifierInfo::GetDeclaringScriptForField(const string& field) const
	{
	record_field_map::const_iterator it = fields.find(field);

	if ( it == fields.end() )
		return "";

	return it->second->from_script;
	}

string IdentifierInfo::DoReStructuredText(bool roles_only) const
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

			if ( broxygen::prettify_params(s) )
				d.NL();

			d.Add(s.c_str());
			}
		else
			d.Add(comments[i].c_str());
		}

	return d.Description();
	}

time_t IdentifierInfo::DoGetModificationTime() const
	{
	// Could probably get away with just checking the set of scripts that
	// contributed to the ID declaration/redefinitions, but this is easier...
	return declaring_script->GetModificationTime();
	}
