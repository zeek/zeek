// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/ScriptInfo.h"
#include "zeek/zeekygen/IdentifierInfo.h"
#include "zeek/zeekygen/ReStructuredTextTable.h"
#include "zeek/zeekygen/utils.h"
#include "zeek/zeekygen/Manager.h"

#include "zeek/Scope.h"
#include "zeek/DebugLogger.h"
#include "zeek/Reporter.h"
#include "zeek/Desc.h"
#include "zeek/Type.h"

using namespace std;

namespace zeek::zeekygen::detail {

bool IdInfoComp::operator ()(const IdentifierInfo* lhs,
                             const IdentifierInfo* rhs) const
	{
	return lhs->Name() < rhs->Name();
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
                           const id_info_list& id_list)
	{
	if ( id_list.empty() )
		return "";

	ReStructuredTextTable table(2);

	for ( id_info_list::const_iterator it = id_list.begin();
	      it != id_list.end(); ++it )
		{
		auto* id = (*it)->GetID();
		ODesc d;
		d.SetQuotes(true);
		id->DescribeReSTShort(&d);
		add_summary_rows(d, summary_comment((*it)->GetComments()), &table);
		}

	return make_heading(heading, underline) + table.AsString(border)
	        + "\n";
	}

static string make_redef_summary(const string& heading, char underline,
                                 char border, const string& from_script,
                                 const id_info_set& id_set)
	{
	if ( id_set.empty() )
		return "";

	ReStructuredTextTable table(2);

	for ( id_info_set::const_iterator it = id_set.begin(); it != id_set.end();
	      ++it )
		{
		auto* id = (*it)->GetID();
		ODesc d;
		d.SetQuotes(true);
		id->DescribeReSTShort(&d);

		typedef list<IdentifierInfo::Redefinition> redef_list;
		redef_list redefs = (*it)->GetRedefs(from_script);

		for ( redef_list::const_iterator iit = redefs.begin();
		      iit != redefs.end(); ++iit )
			{
			add_summary_rows(d, summary_comment(iit->comments), &table);

			if ( ! id->IsType() )
				continue;

			if ( id->GetType()->Tag() == TYPE_ENUM )
				{
				for ( const auto& [enum_name, v] : id->GetType()->AsEnumType()->Names() )
					{
					auto info = zeek::detail::zeekygen_mgr->GetIdentifierInfo(enum_name);

					if ( ! info )
						continue;

					if ( ! info->IsFromRedef() )
						continue;

					if ( ! info->GetDeclaringScript() )
						continue;

					if ( info->GetDeclaringScript()->Name() != from_script )
						continue;

					vector<string> row;
					row.emplace_back("");
					row.emplace_back("");
					table.AddRow(row);

					auto comments = info->GetComments();
					auto summary_comments = summary_comment(comments);
					auto enum_id = info->GetID();

					auto colon = summary_comments.empty() ? "" : ":";
					row[1] = util::fmt("* :zeek:enum:`%s`%s", enum_id->Name(), colon);
					table.AddRow(row);

					for ( auto& sc : summary_comments )
						{
						row[1] = util::fmt("  %s", sc.data());
						table.AddRow(row);
						}
					}
				}
				else if ( id->GetType()->Tag() == TYPE_RECORD )
					{
					auto info = zeek::detail::zeekygen_mgr->GetIdentifierInfo(id->Name());

					if ( ! info || ! info->GetDeclaringScript() )
						continue;

					auto rt = id->GetType()->AsRecordType();
					bool added_new_field_docs = false;

					for ( auto i = 0; i < rt->NumFields(); ++i )
						{
						auto field_name = rt->FieldName(i);

						if ( ! info->FieldIsFromRedef(field_name) )
							continue;

						auto declaring_script = info->GetDeclaringScriptForField(field_name);

						if ( declaring_script != from_script )
							continue;

						vector<string> row;
						row.emplace_back("");
						row.emplace_back("");
						table.AddRow(row);

						if ( ! added_new_field_docs )
							{
							added_new_field_docs = true;
							row[1] = util::fmt(":New Fields: :zeek:type:`%s`", id->Name());
							table.AddRow(row);
							row[1] = "";
							table.AddRow(row);
							}

						auto td = rt->FieldDecl(i);

						ODesc fd;
						fd.SetQuotes(true);
						td->DescribeReST(&fd, true);

						row[1] = util::fmt("  %s", fd.Description());
						table.AddRow(row);

						auto comments = info->GetFieldComments(field_name);
						auto summary_comments = summary_comment(comments);

						for ( auto& sc : summary_comments )
							{
							row[1] = util::fmt("    %s", sc.data());
							table.AddRow(row);
							}
						}
					}
			}
		}

	return make_heading(heading, underline) + table.AsString(border)
	        + "\n";
	}

static string make_details(const string& heading, char underline,
                           const id_info_list& id_list)
	{
	if ( id_list.empty() )
		return "";

	string rval = make_heading(heading, underline);

	for ( id_info_list::const_iterator it = id_list.begin();
	      it != id_list.end(); ++it )
		{
		rval += (*it)->ReStructuredText();
		rval += "\n\n";
		}

	return rval;
	}

static string make_redef_details(const string& heading, char underline,
                                 const id_info_set& id_set)
	{
	if ( id_set.empty() )
		return "";

	string rval = make_heading(heading, underline);

	for ( id_info_set::const_iterator it = id_set.begin();
	      it != id_set.end(); ++it )
		{
		rval += (*it)->ReStructuredText(true);
		rval += "\n\n";
		}

	return rval;
	}

ScriptInfo::ScriptInfo(const string& arg_name, const string& arg_path)
    : Info(),
      name(arg_name), path(arg_path),
      is_pkg_loader(util::detail::is_package_loader(name)),
      dependencies(), module_usages(), comments(), id_info(),
      redef_options(), constants(), state_vars(), types(), events(), hooks(),
      functions(), redefs()
	{
	}

void ScriptInfo::AddIdentifierInfo(IdentifierInfo* info)
	{
	id_info[info->Name()] = info;
	}

void ScriptInfo::DoInitPostScript()
	{
	for ( id_info_map::const_iterator it = id_info.begin();
	      it != id_info.end(); ++it )
		{
		IdentifierInfo* info = it->second;
		auto* id = info->GetID();

		if ( ! is_public_api(id) )
			continue;

		if ( id->IsType() )
			{
			types.push_back(info);
			DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as a type",
			        id->Name(), name.c_str());
			continue;
			}

		if ( IsFunc(id->GetType()->Tag()) )
			{
			switch ( id->GetType()->AsFuncType()->Flavor() ) {
			case FUNC_FLAVOR_HOOK:
				DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as a hook",
				        id->Name(), name.c_str());
				hooks.push_back(info);
				break;
			case FUNC_FLAVOR_EVENT:
				DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as a event",
				        id->Name(), name.c_str());
				events.push_back(info);
				break;
			case FUNC_FLAVOR_FUNCTION:
				DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as a function",
				        id->Name(), name.c_str());
				functions.push_back(info);
				break;
			default:
				reporter->InternalError("Invalid function flavor");
				break;
			}

			continue;
			}

		if ( id->IsConst() )
			{
			if ( id->GetAttr(zeek::detail::ATTR_REDEF) )
				{
				DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as a redef_option",
				        id->Name(), name.c_str());
				redef_options.push_back(info);
				}
			else
				{
				DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as a constant",
				        id->Name(), name.c_str());
				constants.push_back(info);
				}

			continue;
			}
		else if ( id->IsOption() )
			{
			DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as an runtime option",
							id->Name(), name.c_str());
			options.push_back(info);

			continue;
			}

		if ( id->GetType()->Tag() == TYPE_ENUM )
			// Enums are always referenced/documented from the type's
			// documentation.
			continue;

		DBG_LOG(DBG_ZEEKYGEN, "Filter id '%s' in '%s' as a state variable",
		        id->Name(), name.c_str());
		state_vars.push_back(info);
		}

	// The following enum types are automatically created internally in Bro,
	// so just manually associating them with scripts for now.
	if ( name == "base/frameworks/input/main.zeek" )
		{
		const auto& id = zeek::detail::global_scope()->Find("Input::Reader");
		types.push_back(new IdentifierInfo(id, this));
		}
	else if ( name == "base/frameworks/logging/main.zeek" )
		{
		const auto& id = zeek::detail::global_scope()->Find("Log::Writer");
		types.push_back(new IdentifierInfo(id, this));
		}
	}

vector<string> ScriptInfo::GetComments() const
	{
	return comments;
	}

string ScriptInfo::DoReStructuredText(bool roles_only) const
	{
	string rval;

	rval += ":tocdepth: 3\n\n";
	rval += make_heading(name, '=');

	for ( string_set::const_iterator it = module_usages.begin();
	      it != module_usages.end(); ++it )
		rval += ".. zeek:namespace:: " + *it + "\n";

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

			string path = util::find_script_file(*it, util::zeek_path());
			string doc = *it;

			if ( ! path.empty() && util::is_dir(path.c_str()) )
				// Reference the package.
				doc += "/index";

			rval += util::fmt(":doc:`%s </scripts/%s>`", it->c_str(), doc.c_str());
			}

		rval += "\n";
		}

	//rval += util::fmt(":Source File: :download:`/scripts/%s`\n", name.c_str());
	rval += "\n";
	rval += make_heading("Summary", '~');
	rval += make_summary("Runtime Options", '#', '=', options);
	rval += make_summary("Redefinable Options", '#', '=', redef_options);
	rval += make_summary("Constants", '#', '=', constants);
	rval += make_summary("State Variables", '#', '=', state_vars);
	rval += make_summary("Types", '#', '=', types);
	rval += make_redef_summary("Redefinitions", '#', '=', name, redefs);
	rval += make_summary("Events", '#', '=', events);
	rval += make_summary("Hooks", '#', '=', hooks);
	rval += make_summary("Functions", '#', '=', functions);
	rval += "\n";
	rval += make_heading("Detailed Interface", '~');
	rval += make_details("Runtime Options", '#', options);
	rval += make_details("Redefinable Options", '#', redef_options);
	rval += make_details("Constants", '#', constants);
	rval += make_details("State Variables", '#', state_vars);
	rval += make_details("Types", '#', types);
	//rval += make_redef_details("Redefinitions", '#', redefs);
	rval += make_details("Events", '#', events);
	rval += make_details("Hooks", '#', hooks);
	rval += make_details("Functions", '#', functions);

	return rval;
	}

time_t ScriptInfo::DoGetModificationTime() const
	{
	time_t most_recent = get_mtime(path);

	for ( string_set::const_iterator it = dependencies.begin();
	      it != dependencies.end(); ++it )
		{
		Info* info = zeek::detail::zeekygen_mgr->GetScriptInfo(*it);

		if ( ! info )
			{
			string pkg_name = *it + "/__load__.zeek";
			info = zeek::detail::zeekygen_mgr->GetScriptInfo(pkg_name);

			if ( ! info )
				reporter->InternalWarning("Zeekygen failed to get mtime of %s",
				                          it->c_str());
			continue;
			}

		time_t dep_mtime = info->GetModificationTime();

		if ( dep_mtime > most_recent )
			most_recent = dep_mtime;
		}

	return most_recent;
	}

} // namespace zeek::zeekygen::detail
