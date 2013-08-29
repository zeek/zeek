// See the file "COPYING" in the main distribution directory for copyright.

#include <cstdlib>

#include "UID.h"

using namespace Bro;
using namespace std;

void UID::Set(bro_uint_t bits, const std::vector<uint64>& v)
	{
	uid.clear();

	div_t res = div(bits, 64);
	size_t size = res.rem ? res.quot + 1 : res.quot;

	for ( size_t i = 0; i < size; ++i )
		uid.push_back(i < v.size() ? v[i] : calculate_unique_id());

	if ( res.rem )
		uid[0] >>= 64 - res.rem;
	}

string UID::Base62(const std::string& prefix) const
	{
	char tmp[64]; // technically, this should dynamically scale based on size
	string rval(prefix);

	for ( size_t i = 0; i < uid.size(); ++i )
		rval.append(uitoa_n(uid[i], tmp, sizeof(tmp), 62));

	return rval;
	}

bool Bro::operator==(const UID& u1, const UID& u2)
	{
	if ( u1.uid.size() != u2.uid.size() )
		return false;

	for ( size_t i = 0; i < u1.uid.size(); ++i )
		if ( u1.uid[i] != u2.uid[i] )
			return false;

	return true;
	}
