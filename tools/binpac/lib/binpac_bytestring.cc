#define binpac_regex_h

#include <stdlib.h>
#include "binpac_bytestring.h"

namespace binpac 
{

std::string std_string(bytestring const *s)
	{
	return std::string((const char *) s->begin(), (const char *) s->end());
	}

int bytestring_to_int(bytestring const *s)
	{
	return atoi((const char *) s->begin());
	}

double bytestring_to_double(bytestring const *s)
	{
	return atof((const char *) s->begin());
	}

}  // namespace binpac
