// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/utils.h"

#include <sys/stat.h>
#include <cerrno>

#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/plugin/Manager.h"

using namespace std;

namespace zeek::zeekygen::detail
	{

bool prettify_params(string& s)
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

bool is_public_api(const zeek::detail::ID* id)
	{
	return (id->Scope() == zeek::detail::SCOPE_GLOBAL) ||
	       (id->Scope() == zeek::detail::SCOPE_MODULE && id->IsExport());
	}

time_t get_mtime(const string& filename)
	{
	struct stat s;

	if ( stat(filename.c_str(), &s) < 0 )
		reporter->InternalError("Zeekygen failed to stat file '%s': %s", filename.c_str(),
		                        strerror(errno));

	return s.st_mtime;
	}

string make_heading(const string& heading, char underline)
	{
	return heading + "\n" + string(heading.size(), underline) + "\n";
	}

size_t end_of_first_sentence(const string& s)
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

bool is_all_whitespace(const string& s)
	{
	for ( size_t i = 0; i < s.size(); ++i )
		if ( ! isspace(s[i]) )
			return false;

	return true;
	}

string redef_indication(const string& from_script)
	{
	return util::fmt("(present if :doc:`/scripts/%s` is loaded)", from_script.c_str());
	}

std::string normalize_script_path(std::string_view path)
	{
	if ( auto p = plugin_mgr->LookupPluginByPath(path) )
		{
		auto rval = util::detail::normalize_path(path);
		auto prefix = util::SafeBasename(p->PluginDirectory()).result;

		// Collision avoidance when there's no _ in the plugin basename such
		// as when using ./build within a plugin checkout for testing. Include
		// the parent in the normalized path assuming it's unique.
		if ( prefix.find('_') == std::string::npos )
			{
			auto parent = util::SafeBasename(util::SafeDirname(p->PluginDirectory()).result).result;
			prefix = parent + "/" + prefix;
			}

		return prefix + "/" + rval.substr(p->PluginDirectory().size() + 1);
		}

	return util::detail::without_zeekpath_component(path);
	}

std::optional<std::string> source_code_range(const zeek::detail::ID* id)
	{
	const auto& type = id->GetType();

	if ( ! type )
		return {};

	// Some object locations won't end up capturing concrete syntax of closing
	// braces on subsequent line -- of course that doesn't have to always be
	// case, but it's true for current code style and the possibility of
	// capturing an extra line of context is not harmful (human reader shouldn't
	// be too confused by it).
	int extra_lines = 0;
	const zeek::detail::Location* loc = &zeek::detail::no_location;

	switch ( type->Tag() )
		{
		case TYPE_FUNC:
			{
			const auto& v = id->GetVal();

			if ( v && v->AsFunc()->GetBodies().size() == 1 )
				{
				// Either a function or an event/hook with single body can
				// report that single, continuous range.
				loc = v->AsFunc()->GetBodies()[0].stmts->GetLocationInfo();
				++extra_lines;
				}
			else
				loc = id->GetLocationInfo();
			}
			break;
		case TYPE_ENUM:
			// Fallthrough
		case TYPE_RECORD:
			if ( id->IsType() )
				{
				loc = type->GetLocationInfo();

				if ( zeek::util::ends_with(loc->filename, ".bif.zeek") )
					// Source code won't be available to reference, so fall back
					// to identifier location which may actually be in a regular
					// .zeek script.
					loc = id->GetLocationInfo();
				else
					++extra_lines;
				}
			else
				loc = id->GetLocationInfo();

			break;
		default:
			loc = id->GetLocationInfo();
			break;
		}

	if ( loc == &zeek::detail::no_location )
		return {};

	return util::fmt("%s %d %d", normalize_script_path(loc->filename).data(), loc->first_line,
	                 loc->last_line + extra_lines);
	}

	} // namespace zeek::zeekygen::detail
