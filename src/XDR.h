// $Id: XDR.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef xdr_h
#define xdr_h

#include <sys/types.h>
#include <netinet/in.h>

#include "util.h"

inline int XDR_aligned(const u_char* buf)
	{
	return (((unsigned long) buf) & 0x3) == 0;
	}

extern uint32 extract_XDR_uint32(const u_char*& buf, int& len);
extern double extract_XDR_uint64_as_double(const u_char*& buf, int& len);
extern double extract_XDR_time(const u_char*& buf, int& len);
extern const u_char* extract_XDR_opaque(const u_char*& buf, int& len,
					int& n, int max_len=8192);
extern uint32 skip_XDR_opaque_auth(const u_char*& buf, int& len);

#endif
