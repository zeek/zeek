%extern{
#include <cstring>
#include <binpac_bytestring.h>
%}

function bytestring_casecmp(s1: const_bytestring, s2: const_charptr): int
	%{
	int r = strncasecmp(reinterpret_cast<const char*>(s1.begin()), s2, s1.length());
	if ( r == 0 )
		return s2[s1.length()] == '\0' ? 0 : -1;
	else
		return r;
	%}

# True if s2 is a (case-insensitive) prefix of s1.
function bytestring_caseprefix(s1: const_bytestring, s2: const_charptr): bool
	%{
	return strncasecmp(reinterpret_cast<const char*>(s1.begin()), s2, strlen(s2)) == 0;
	%}

function bytestring_to_int(s: const_bytestring, base: int): int
	%{
	return strtol(std_str(s).c_str(), nullptr, base);
	%}

function bytestring_to_double(s: const_bytestring): double
	%{
	return atof(std_str(s).c_str());
	%}
