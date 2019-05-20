// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "zeek-config.h"

#include "XDR.h"

#include "events.bif.h"

using namespace analyzer::rpc;

uint32 analyzer::rpc::extract_XDR_uint32(const u_char*& buf, int& len)
	{
	if ( ! buf )
		return 0;

	if ( len < 4 )
		{
		buf = 0;
		return 0;
		}

	// Takes care of alignment and endianess differences. 
	uint32 bits32 = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

	buf += 4;
	len -= 4;

	return bits32;
	}

uint64 analyzer::rpc::extract_XDR_uint64(const u_char*& buf, int& len)
	{
	if ( ! buf || len < 8 )
		{
		buf = 0;
		return 0;
		}

	uint64 uhi = extract_XDR_uint32(buf, len);
	uint64 ulo = extract_XDR_uint32(buf, len);

	return (uhi << 32) + ulo;
	}

double analyzer::rpc::extract_XDR_time(const u_char*& buf, int& len)
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

const u_char* analyzer::rpc::extract_XDR_opaque(const u_char*& buf, int& len, int& n, int max_len, bool short_buf_ok)
	{
	n = int(extract_XDR_uint32(buf, len));
	if ( ! buf )
		return 0;

	if ( short_buf_ok )
		n = std::min(n, len);

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

const u_char* analyzer::rpc::extract_XDR_opaque_fixed(const u_char*& buf, int& len, int n)
	{
	if ( ! buf )
		return 0;
	if ( n < 0 || n > len)
		{
		buf = 0;
		return 0;
		}
	int n4 = ((n + 3) >> 2) << 2;	// n rounded up to next multiple of 4

	len -= n4;
	const u_char* opaque = buf;
	buf += n4;

	return opaque;
	}


uint32 analyzer::rpc::skip_XDR_opaque_auth(const u_char*& buf, int& len)
	{
	uint32 auth_flavor = extract_XDR_uint32(buf, len);
	if ( ! buf )
		return 0;

	int n;
	(void) extract_XDR_opaque(buf, len, n, 400);

	return auth_flavor;
	}
