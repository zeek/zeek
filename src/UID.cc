// See the file "COPYING" in the main distribution directory for copyright.

#include <cstdlib>

#include "UID.h"

using namespace Bro;
using namespace std;

void UID::Set(bro_uint_t bits, const uint64* v, size_t n)
	{
	initialized = true;

	for ( size_t i = 0; i < BRO_UID_LEN; ++i )
		uid[i] = 0;

	if ( bits > BRO_UID_LEN * 64 )
		bits = BRO_UID_LEN * 64;

	div_t res = div(bits, 64);
	size_t size = res.rem ? res.quot + 1 : res.quot;

	for ( size_t i = 0; i < size; ++i )
		uid[i] = v && i < n ? v[i] : calculate_unique_id();

	if ( res.rem )
		uid[0] >>= 64 - res.rem;
	}
