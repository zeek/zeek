#include "utils.h"

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
				subst = ":param " + identifier;

			s.replace(identifier_start_pos, identifier.size(), subst);
			return true;
			}

		// Don't need to change anything.
		return false;
		}

	return false;
	}
