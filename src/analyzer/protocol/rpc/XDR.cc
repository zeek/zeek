// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/rpc/XDR.h"

#include "zeek/zeek-config.h"

#include <algorithm>
#include <cstring>

#include "zeek/analyzer/protocol/rpc/events.bif.h"

uint32_t zeek::analyzer::rpc::extract_XDR_uint32(const u_char*& buf, int& len)
	{
	if ( ! buf )
		return 0;

	if ( len < 4 )
		{
		buf = nullptr;
		return 0;
		}

	// Takes care of alignment and endianness differences.
	uint32_t buf_bits32;
	memcpy(&buf_bits32, buf, 4);
	uint32_t bits32 = ntohl(buf_bits32);

	buf += 4;
	len -= 4;

	return bits32;
	}

uint64_t zeek::analyzer::rpc::extract_XDR_uint64(const u_char*& buf, int& len)
	{
	if ( ! buf || len < 8 )
		{
		buf = nullptr;
		return 0;
		}

	uint64_t uhi = extract_XDR_uint32(buf, len);
	uint64_t ulo = extract_XDR_uint32(buf, len);

	return (uhi << 32) + ulo;
	}

double zeek::analyzer::rpc::extract_XDR_time(const u_char*& buf, int& len)
	{
	if ( ! buf || len < 8 )
		{
		buf = nullptr;
		return 0.0;
		}

	uint32_t uhi = extract_XDR_uint32(buf, len);
	uint32_t ulo = extract_XDR_uint32(buf, len);

	return double(uhi) + double(ulo) / 1e9;
	}

const u_char* zeek::analyzer::rpc::extract_XDR_opaque(const u_char*& buf, int& len, int& n,
                                                      int max_len, bool short_buf_ok)
	{
	n = int(extract_XDR_uint32(buf, len));
	if ( ! buf )
		return nullptr;

	if ( short_buf_ok )
		n = std::min(n, len);

	if ( n < 0 || n > len || n > max_len )
		{ // ### Should really flag this as a different sort of error.
		buf = nullptr;
		return nullptr;
		}

	int n4 = ((n + 3) >> 2) << 2; // n rounded up to next multiple of 4

	len -= n4;
	const u_char* opaque = buf;
	buf += n4;

	return opaque;
	}

const u_char* zeek::analyzer::rpc::extract_XDR_opaque_fixed(const u_char*& buf, int& len, int n)
	{
	if ( ! buf )
		return nullptr;
	if ( n < 0 || n > len )
		{
		buf = nullptr;
		return nullptr;
		}
	int n4 = ((n + 3) >> 2) << 2; // n rounded up to next multiple of 4

	len -= n4;
	const u_char* opaque = buf;
	buf += n4;

	return opaque;
	}

uint32_t zeek::analyzer::rpc::skip_XDR_opaque_auth(const u_char*& buf, int& len)
	{
	uint32_t auth_flavor = extract_XDR_uint32(buf, len);
	if ( ! buf )
		return 0;

	int n;
	(void)extract_XDR_opaque(buf, len, n, 400);

	return auth_flavor;
	}
