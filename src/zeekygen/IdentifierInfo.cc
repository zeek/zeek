// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/IdentifierInfo.h"

#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Val.h"
#include "zeek/zeekygen/ScriptInfo.h"
#include "zeek/zeekygen/utils.h"

using namespace std;

namespace zeek::zeekygen::detail
	{

IdentifierInfo::IdentifierInfo(zeek::detail::IDPtr arg_id, ScriptInfo* script, bool redef)
	: Info(), comments(), id(std::move(arg_id)), initial_val(), redefs(), fields(),
	  last_field_seen(), declaring_script(script), from_redef(redef)
	{
	if ( id->GetVal() && (id->IsOption() || id->IsRedefinable()) )
		initial_val = id->GetVal()->Clone();
	}

IdentifierInfo::~IdentifierInfo()
	{
	for ( redef_list::const_iterator it = redefs.begin(); it != redefs.end(); ++it )
		delete *it;

	for ( record_field_map::const_iterator it = fields.begin(); it != fields.end(); ++it )
		delete it->second;
	}

void IdentifierInfo::AddRedef(const string& script, zeek::detail::InitClass ic,
                              zeek::detail::ExprPtr init_expr, const vector<string>& comments)
	{
	Redefinition* redef = new Redefinition(script, ic, std::move(init_expr), comments);
	redefs.push_back(redef);
	}

void IdentifierInfo::AddRecordField(const TypeDecl* field, const string& script,
                                    vector<string>& comments, bool from_redef)
	{
	RecordField* rf = new RecordField();
	rf->field = new TypeDecl(*field);
	rf->from_script = script;
	rf->comments = comments;
	rf->from_redef = from_redef;

	auto [it, inserted] = fields.emplace(rf->field->id, rf);

	if ( ! inserted )
		{
		delete it->second;
		it->second = rf;
		}

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

list<IdentifierInfo::Redefinition> IdentifierInfo::GetRedefs(const string& from_script) const
	{
	list<Redefinition> rval;

	for ( redef_list::const_iterator it = redefs.begin(); it != redefs.end(); ++it )
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

bool IdentifierInfo::FieldIsFromRedef(const std::string& field) const
	{
	auto it = fields.find(field);

	if ( it == fields.end() )
		return false;

	return it->second->from_redef;
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

		if ( IsFunc(id->GetType()->Tag()) )
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

time_t IdentifierInfo::DoGetModificationTime() const
	{
	// Could probably get away with just checking the set of scripts that
	// contributed to the ID declaration/redefinitions, but this is easier...
	return declaring_script->GetModificationTime();
	}

IdentifierInfo::Redefinition::Redefinition(std::string arg_script, zeek::detail::InitClass arg_ic,
                                           zeek::detail::ExprPtr arg_expr,
                                           std::vector<std::string> arg_comments)
	: from_script(std::move(arg_script)), ic(arg_ic), init_expr(std::move(arg_expr)),
	  comments(std::move(arg_comments))
	{
	}

IdentifierInfo::Redefinition::~Redefinition() = default;

IdentifierInfo::RecordField::~RecordField()
	{
	delete field;
	}

	} // namespace zeek::zeekygen::detail
