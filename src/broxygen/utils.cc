// See the file "COPYING" in the main distribution directory for copyright.

#include "utils.h"

#include "Reporter.h"

#include <sys/stat.h>
#include <errno.h>

using namespace broxygen;
using namespace std;

bool broxygen::prettify_params(string& s)
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
				subst = ":" + identifier;

			s.replace(identifier_start_pos, identifier.size(), subst);
			return true;
			}

		// Don't need to change anything.
		return false;
		}

	return false;
	}

bool broxygen::is_public_api(const ID* id)
	{
	return (id->Scope() == SCOPE_GLOBAL) ||
	       (id->Scope() == SCOPE_MODULE && id->IsExport());
	}

time_t broxygen::get_mtime(const string& filename)
	{
	struct stat s;

	if ( stat(filename.c_str(), &s) < 0 )
		reporter->InternalError("Broxygen failed to stat file '%s': %s",
		                        filename.c_str(), strerror(errno));

	return s.st_mtime;
	}

string broxygen::make_heading(const string& heading, char underline)
	{
	return heading + "\n" + string(heading.size(), underline) + "\n";
	}

size_t broxygen::end_of_first_sentence(const string& s)
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

bool broxygen::is_all_whitespace(const string& s)
	{
	for ( size_t i = 0; i < s.size(); ++i )
		if ( ! isspace(s[i]) )
			return false;

	return true;
	}

string broxygen::redef_indication(const string& from_script)
	{
	return fmt("(present if :doc:`/scripts/%s` is loaded)",
	           from_script.c_str());
	}
