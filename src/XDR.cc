// $Id: XDR.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "XDR.h"

uint32 extract_XDR_uint32(const u_char*& buf, int& len)
	{
	if ( ! buf )
		return 0;

	if ( len < 4 )
		{
		buf = 0;
		return 0;
		}

	uint32 bits32 = XDR_aligned(buf) ? *(uint32*) buf :
		((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);

	buf += 4;
	len -= 4;

	return ntohl(bits32);
	}

double extract_XDR_uint64_as_double(const u_char*& buf, int& len)
	{
	if ( ! buf || len < 8 )
		{
		buf = 0;
		return 0.0;
		}

	uint32 uhi = extract_XDR_uint32(buf, len);
	uint32 ulo = extract_XDR_uint32(buf, len);

	return double(uhi) * 4294967296.0 + double(ulo);
	}

double extract_XDR_time(const u_char*& buf, int& len)
	{
	if ( ! buf || len < 8 )
		{
		buf = 0;
		return 0.0;
		}

	uint32 uhi = extract_XDR_uint32(buf, len);
	uint32 ulo = extract_XDR_uint32(buf, len);

	return double(uhi) + double(ulo) / 1e9;
	}

const u_char* extract_XDR_opaque(const u_char*& buf, int& len, int& n, int max_len)
	{
	n = int(extract_XDR_uint32(buf, len));
	if ( ! buf )
		return 0;

	if ( n < 0 || n > len || n > max_len )
		{ // ### Should really flag this as a different sort of error.
		buf = 0;
		return 0;
		}

	int n4 = ((n + 3) >> 2) << 2;	// n rounded up to next multiple of 4

	len -= n4;
	const u_char* opaque = buf;
	buf += n4;

	return opaque;
	}

uint32 skip_XDR_opaque_auth(const u_char*& buf, int& len)
	{
	uint32 auth_flavor = extract_XDR_uint32(buf, len);
	if ( ! buf )
		return 0;

	int n;
	(void) extract_XDR_opaque(buf, len, n, 400);

	return auth_flavor;
	}
